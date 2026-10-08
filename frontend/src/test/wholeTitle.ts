// Shared checks for the hunt-title tests. The owner reported that hunt titles
// were cut short and ended in an ellipsis, and that the full text was nowhere.
// A surface may let the browser clamp a title, but the full text must stay in
// the DOM or in a `title` attribute one hover away.

/** A 180 character hunt objective on one line. */
export const TITLE_180 =
  'Hunt for internal hosts that beacon to rare external addresses on a fixed cadence, ' +
  'name each destination, and state the interval and the jitter of every beacon in this hunt window.';

/** The text an element holds directly, without the text of its children. */
function ownText(el: Element): string {
  return Array.from(el.childNodes)
    .filter((n) => n.nodeType === 3)
    .map((n) => n.textContent ?? '')
    .join('')
    .trim();
}

/** Whether `el` or an ancestor carries a `title` attribute that holds `full`. */
function heldOnHover(el: Element | null, full: string): boolean {
  for (let a = el; a; a = a.parentElement) {
    if (a.getAttribute('title')?.includes(full)) return true;
  }
  return false;
}

/**
 * The texts under `root` that are a cut of `full` with a trailing ellipsis and
 * no `title` that holds the whole text. A test expects an empty list.
 *
 * A loading line such as "Loading hunts…" also ends in an ellipsis. It is not a
 * cut of the title, so the check counts a text only when its last characters
 * before the ellipsis occur in `full`.
 */
export function bareCuts(root: ParentNode, full: string): string[] {
  const out: string[] = [];
  for (const el of Array.from(root.querySelectorAll('*'))) {
    const text = ownText(el);
    const m = text.match(/^([\s\S]*?)(?:…|\.\.\.)$/);
    if (!m) continue;
    const tail = m[1].trimEnd().slice(-20);
    if (tail.length < 8 || !full.includes(tail)) continue;
    if (!heldOnHover(el, full)) out.push(text);
  }
  return out;
}

/** Whether the whole of `full` is in the text of `root` or in a `title` under it. */
export function showsWhole(root: ParentNode & { textContent: string | null }, full: string): boolean {
  const flat = (s: string) => s.replace(/\s+/g, ' ');
  if (flat(root.textContent ?? '').includes(flat(full))) return true;
  return Array.from(root.querySelectorAll('[title]')).some((el) =>
    (el.getAttribute('title') ?? '').includes(full),
  );
}
