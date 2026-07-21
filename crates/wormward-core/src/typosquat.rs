//! Name-level typosquat recognition for npm dependencies — the FIRST half of delivery-vector
//! detection. A [`typosquat_of`] hit is only a WEAK signal on its own (legit ecosystems are full
//! of `<tool>-<plugin>` names); the scanner promotes it to a visible finding ONLY when the package
//! itself also exhibits dropper behaviour (see `scanner::scan_dependency_typosquats`). This module
//! is pure and value-independent so it can be tested exhaustively against a large legit-name corpus.

/// Popular npm package names a typosquat commonly MISSPELLS (edit-distance 1). Kept to well-known,
/// ≥5-char names so a one-edit neighbour is a strong tell rather than a coincidence.
const POPULAR: &[&str] = &[
    "react", "angular", "svelte", "preact", "next", "nuxt", "vite", "webpack", "rollup", "esbuild",
    "express", "fastify", "axios", "lodash", "chalk", "commander", "dotenv", "tailwindcss",
    "postcss", "autoprefixer", "eslint", "prettier", "typescript", "jest", "mocha", "vitest",
    "playwright", "puppeteer", "dayjs", "moment", "mongoose", "sequelize", "prisma", "nodemailer",
    "socket.io", "discord.js", "ethers", "web3", "coingecko",
];

/// Roots a typosquatter DECORATES with extra words (`tailwindcss-style-animate`,
/// `chalk-logger`, `coingecko-liard`). Deliberately TINY: only roots the PolinRider family actually
/// squats and whose legit ecosystem does NOT sprawl into third-party `<root>-<word>` names. Popular
/// roots with huge plugin ecosystems (`react`, `next`, `vite`, `eslint`, `express`, `axios`, …) are
/// EXCLUDED — `react-icons`/`lucide-react`/`react-toastify` are legit, so they would false-positive.
/// A decoration hit is a WEAK signal that only ever fires WITH dropper-behaviour corroboration (the
/// scanner never emits a name-only lead for a decoration); misspellings are the FP-safe name signal.
const SQUAT_BASES: &[&str] = &["tailwindcss", "tailwind", "chalk", "coingecko"];

/// Legit packages that LOOK like typosquats (a decorated popular root, or a one-edit neighbour of a
/// popular name) but are genuine, widely-used packages. Belt-and-suspenders for the community/Low
/// tier — the behaviour gate already keeps them out of the default (Medium) tier. Not exhaustive:
/// anything not here still needs dropper behaviour to be reported.
const LEGIT_ALLOW: &[&str] = &[
    "preact", "tailwindcss-animate", "tailwindcss-animated", "tailwind-merge", "tailwind-scrollbar",
    "tailwind-variants", "chalk-animation", "react-dom", "react-router", "react-router-dom",
    "react-redux", "next-auth", "next-themes", "next-sitemap", "svelte-check", "vite-node",
    "express-session", "axios-retry", "axios-mock-adapter", "web3modal", "ethers-multicall",
];

/// Prefix conventions that are established, overwhelmingly-legit plugin namespaces — never treated
/// as decoration typosquats (they would swamp the signal with false positives).
const ALLOW_PREFIXES: &[&str] = &[
    "eslint-plugin-", "eslint-config-", "vite-plugin-", "rollup-plugin-", "babel-plugin-",
    "babel-preset-", "stylelint-", "postcss-", "remark-", "rehype-", "@",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TyposquatKind {
    /// A one-edit misspelling of a popular name (`expres` → `express`).
    Misspelling,
    /// A popular root decorated with extra words (`tailwindcss-style-animate` → `tailwindcss`).
    Decoration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TyposquatHit {
    /// The popular package this name mimics.
    pub of: &'static str,
    pub kind: TyposquatKind,
}

/// True if `a` and `b` are within Damerau-agnostic edit distance 1 (one insert, delete, or
/// substitute). Cheap and length-guarded — returns false immediately when the lengths differ by
/// more than one.
fn edit_distance_le_1(a: &str, b: &str) -> bool {
    let (ab, bb) = (a.as_bytes(), b.as_bytes());
    let (la, lb) = (ab.len(), bb.len());
    if la.abs_diff(lb) > 1 {
        return false;
    }
    if la == lb {
        // one substitution, or one adjacent transposition (Damerau) — both classic typosquats.
        let diffs: Vec<usize> = (0..la).filter(|&i| ab[i] != bb[i]).collect();
        return match diffs.as_slice() {
            [_] => true,                                    // exactly one substitution
            [i, j] => *j == *i + 1 && ab[*i] == bb[*j] && ab[*j] == bb[*i], // adjacent swap
            _ => false,                                     // identical (0) or too different
        };
    }
    // lengths differ by one: the longer must equal the shorter with one char inserted
    let (short, long) = if la < lb { (ab, bb) } else { (bb, ab) };
    let mut i = 0;
    let mut j = 0;
    let mut skipped = false;
    while i < short.len() && j < long.len() {
        if short[i] == long[j] {
            i += 1;
            j += 1;
        } else if !skipped {
            skipped = true;
            j += 1; // skip one char in the longer string
        } else {
            return false;
        }
    }
    true
}

/// Does `name` contain `base` as a decoration — a whole token separated by `-`/`_`/`.` on at least
/// one side, with extra content (so `name != base`)?
fn decorated_with(name: &str, base: &str) -> bool {
    if name == base || !name.contains(base) {
        return false;
    }
    let sep = |c: char| c == '-' || c == '_' || c == '.';
    // `base-...`
    if let Some(rest) = name.strip_prefix(base) {
        if rest.starts_with(sep) {
            return true;
        }
    }
    // `...-base`
    if let Some(rest) = name.strip_suffix(base) {
        if rest.ends_with(sep) {
            return true;
        }
    }
    // `...-base-...`
    for (i, _) in name.match_indices(base) {
        let before = name[..i].chars().next_back();
        let after = name[i + base.len()..].chars().next();
        if before.map(sep).unwrap_or(false) && after.map(sep).unwrap_or(false) {
            return true;
        }
    }
    false
}

/// Recognise a dependency name as a likely typosquat of a popular package, or `None`. A WEAK
/// signal by itself (see module docs) — the scanner requires dropper behaviour before promoting a
/// hit to a visible finding.
pub fn typosquat_of(name: &str) -> Option<TyposquatHit> {
    let n = name.trim().to_ascii_lowercase();
    if n.is_empty() {
        return None;
    }
    // Never flag exact popular names, curated legit lookalikes, or established plugin namespaces.
    if POPULAR.contains(&n.as_str())
        || SQUAT_BASES.contains(&n.as_str())
        || LEGIT_ALLOW.contains(&n.as_str())
        || ALLOW_PREFIXES.iter().any(|p| n.starts_with(p))
    {
        return None;
    }
    // Misspelling of a popular name (≥5 chars so a one-edit neighbour is meaningful).
    for &p in POPULAR {
        if p.len() >= 5 && edit_distance_le_1(&n, p) {
            return Some(TyposquatHit { of: p, kind: TyposquatKind::Misspelling });
        }
    }
    // Decoration of a squat root.
    for &b in SQUAT_BASES {
        if decorated_with(&n, b) {
            return Some(TyposquatHit { of: b, kind: TyposquatKind::Decoration });
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- POSITIVE: the real PolinRider delivery names must be recognised (decoration) ---
    #[test]
    fn recognises_polinrider_delivery_packages() {
        for name in [
            "tailwindcss-style-animate",
            "tailwind-mainanimation",
            "tailwind-autoanimation",
            "tailwind-animationbased",
            "tailwindcss-typography-style",
            "tailwindcss-style-modify",
            "tailwindcss-animate-style",
            "tailwind-stylecss",
            "chalk-logger",
            "coingecko-liard",
        ] {
            assert!(typosquat_of(name).is_some(), "PolinRider delivery name must be recognised: {name}");
        }
    }

    // --- POSITIVE: classic misspellings ---
    #[test]
    fn recognises_misspellings() {
        for (name, of) in
            [("expres", "express"), ("axioss", "axios"), ("lodahs", "lodash"), ("tailwindcs", "tailwindcss")]
        {
            let hit = typosquat_of(name);
            assert_eq!(hit.map(|h| h.of), Some(of), "{name} should be a misspelling of {of}");
        }
    }

    // --- NEGATIVE (the FP-safety core): a large legit-name corpus must produce ZERO hits ---
    #[test]
    fn legit_popular_packages_are_never_flagged() {
        const LEGIT: &[&str] = &[
            // exact popular
            "react", "vue", "next", "vite", "chalk", "axios", "lodash", "tailwindcss", "postcss",
            "eslint", "prettier", "typescript", "express", "webpack", "svelte", "nuxt",
            // legit decorated lookalikes (must not FP)
            "tailwindcss-animate", "tailwindcss-animated", "tailwind-merge", "tailwind-scrollbar",
            "tailwind-variants", "chalk-animation", "react-dom", "react-router-dom", "react-redux",
            "next-auth", "next-themes", "preact", "web3modal",
            // established plugin namespaces
            "eslint-plugin-react", "eslint-config-next", "eslint-plugin-import", "vite-plugin-pwa",
            "rollup-plugin-terser", "babel-plugin-macros", "babel-preset-env", "postcss-import",
            "postcss-nested", "stylelint-config-standard", "remark-gfm", "rehype-raw",
            // scoped official
            "@tailwindcss/typography", "@tailwindcss/forms", "@babel/core", "@types/node",
            "@vitejs/plugin-react", "@nestjs/common",
            // unrelated popular packages (no resemblance)
            "zod", "dayjs", "uuid", "commander", "dotenv", "cors", "helmet", "bcrypt", "jsonwebtoken",
            "mongoose", "prisma", "redux", "rxjs", "immer", "clsx", "classnames", "framer-motion",
            "date-fns", "nanoid", "pino", "winston", "yargs", "inquirer", "ora", "boxen",
            // the React ecosystem — `react` is NOT a decoration base, so none of these may flag
            // (this was a real false-positive class caught by auditing in-the-wild dependency names)
            "react-icons", "lucide-react", "react-toastify", "react-hot-toast", "react-scripts",
            "react-slick", "react-spinners", "react-tabs", "react-loader-spinner", "react-stars",
            "next-connect", "vite-tsconfig-paths", "express-rate-limit", "axios-cache-interceptor",
        ];
        let hits: Vec<_> = LEGIT.iter().filter(|n| typosquat_of(n).is_some()).collect();
        assert!(hits.is_empty(), "legit packages must never be flagged as typosquats: {hits:?}");
    }

    #[test]
    fn edit_distance_helper() {
        assert!(edit_distance_le_1("express", "expres")); // deletion
        assert!(edit_distance_le_1("axios", "axioss")); // insertion
        assert!(edit_distance_le_1("chalk", "chalq")); // substitution
        assert!(!edit_distance_le_1("react", "react")); // identical is NOT distance 1
        assert!(!edit_distance_le_1("react", "svelte")); // far
        assert!(!edit_distance_le_1("vue", "value")); // length diff > 1
    }

    #[test]
    fn decoration_requires_token_boundary() {
        // `tailwindcss` embedded as a token → decoration
        assert!(decorated_with("tailwindcss-style-animate", "tailwindcss"));
        assert!(decorated_with("my-tailwind-plugin", "tailwind"));
        // substring that is NOT a token boundary → not decoration
        assert!(!decorated_with("tailwindcssanimate", "tailwindcss")); // glued, no separator
        assert!(!decorated_with("tailwindcss", "tailwindcss")); // identical
    }
}
