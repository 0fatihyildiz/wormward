/** Map raw backend / GitHub errors to plain language; pass anything else through. */
export function humanizeError(e: unknown): string {
  const s = String(e);
  if (/\b401\b|unauthorized|bad credentials/i.test(s))
    return "Authentication failed — check your token in Settings.";
  if (/\b403\b|forbidden|rate limit/i.test(s))
    return "GitHub refused the request — token permissions or rate limit. Check the token's scope, or wait and retry.";
  if (/network|timed? ?out|connection|dns|failed to (fetch|connect|resolve)/i.test(s))
    return "Network error — couldn't reach the server. Check your connection and retry.";
  if (/requires an? (osm|opensourcemalware) token|online scan requires/i.test(s))
    return "Online cross-check needs an OpenSourceMalware token — add one in Settings.";
  return s.replace(/^error:\s*/i, "");
}
