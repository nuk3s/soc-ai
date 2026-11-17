// The owner's rule for an analyst-visible string (2026-11-14): never "run",
// "runs", "member" or "members" for an investigation, and never the retired
// word for the whole network. A test of a campaign surface reads every word
// an analyst can see or hear under its root and expects no hit.

// The bracket keeps the retired word itself out of the source.
const FORBIDDEN = /\b(runs?|members?|est[a]te)\b/i;

/** The text under `root`, and each title and accessible name under it. */
export function readableWords(root: Element): string[] {
  const out = [root.textContent ?? ''];
  for (const el of [root, ...Array.from(root.querySelectorAll('*'))]) {
    for (const attr of ['title', 'aria-label']) {
      const value = el.getAttribute(attr);
      if (value) out.push(value);
    }
  }
  return out.filter((s) => s.trim());
}

/** The strings under `root` that hold a word the owner forbids. A test expects an empty list. */
export function forbiddenWords(root: Element): string[] {
  return readableWords(root).filter((s) => FORBIDDEN.test(s));
}
