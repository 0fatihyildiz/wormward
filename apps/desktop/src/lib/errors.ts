/** Map raw backend / GitHub errors to plain language; pass anything else through. */
export function humanizeError(e: unknown): string {
  const s = String(e);
  if (/\b401\b|unauthorized|bad credentials/i.test(s))
    return "Authentication failed — check your token in Settings.";
  // Check rate limit BEFORE the generic 403: the backend already retried with backoff, so if this
  // surfaces the limit is genuinely still active (or primary quota is exhausted). Distinct from a
  // permissions 403 so the user waits rather than fruitlessly re-checking token scopes.
  const limited = s.match(/limited for ~(\d+) min/);
  // The anti-scraping flag is a different situation than quota: GitHub has judged the
  // traffic pattern abusive, so "try again" alone is bad advice — say what happened and
  // how to avoid re-tripping it. Checked before the generic rate-limit mapping. Anchored
  // on GitHub's actual phrase ("scraping GitHub"), not bare "scraping" — a RateLimited
  // message embeds the request URL, which can contain a repo full name like
  // "me/web-scraping-kit" and would otherwise misclassify a plain rate limit.
  if (/scraping github/i.test(s)) {
    const wait = limited ? `Wait about ${limited[1]} minutes, then` : "Wait a while, then";
    return `GitHub has temporarily flagged this account's API traffic. ${wait} scan fewer repos or orgs at once.`;
  }
  if (/rate limit/i.test(s)) {
    if (limited)
      return `GitHub rate limit reached — wormward paused and retried, but it's still limited for about ${limited[1]} more minutes. Wait and try again.`;
    return "GitHub rate limit reached — wormward paused and retried, but it's still limited. Wait a few minutes and try again.";
  }
  if (/\b403\b|forbidden/i.test(s))
    return "GitHub refused the request — your token is missing a required scope. Give it repo read (and write, to fix) access in Settings.";
  if (/network|timed? ?out|connection|dns|failed to (fetch|connect|resolve)/i.test(s))
    return "Network error — couldn't reach the server. Check your connection and retry.";
  if (/requires an? (osm|opensourcemalware) token|online scan requires/i.test(s))
    return "Online cross-check needs an OpenSourceMalware token — add one in Settings.";
  return s.replace(/^error:\s*/i, "");
}
