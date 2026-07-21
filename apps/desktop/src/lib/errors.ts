/** Map raw backend / GitHub errors to plain language; pass anything else through. */
export function humanizeError(e: unknown): string {
  const s = String(e);
  if (/\b401\b|unauthorized|bad credentials/i.test(s))
    return "Authentication failed — check your token in Settings.";
  // Check rate limit BEFORE the generic 403: the backend already retried with backoff, so if this
  // surfaces the limit is genuinely still active (or primary quota is exhausted). Distinct from a
  // permissions 403 so the user waits rather than fruitlessly re-checking token scopes.
  if (/rate limit/i.test(s))
    return "GitHub rate limit reached — wormward paused and retried, but it's still limited. Wait a few minutes and try again.";
  if (/\b403\b|forbidden/i.test(s))
    return "GitHub refused the request — your token is missing a required scope. Give it repo read (and write, to fix) access in Settings.";
  if (/network|timed? ?out|connection|dns|failed to (fetch|connect|resolve)/i.test(s))
    return "Network error — couldn't reach the server. Check your connection and retry.";
  if (/requires an? (osm|opensourcemalware) token|online scan requires/i.test(s))
    return "Online cross-check needs an OpenSourceMalware token — add one in Settings.";
  return s.replace(/^error:\s*/i, "");
}
