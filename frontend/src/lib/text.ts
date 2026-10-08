/**
 * The word a count shows while the console still reads it.
 *
 * The console showed "…" in its place. The owner banned the ellipsis on
 * 2026-10-07: it hides information and reads as a cut. A count that the
 * console asked for and did not get still reads as a dash.
 */
export const COUNTING = 'counting';

/**
 * The first sentence of a paragraph.
 *
 * A hunt objective runs to several sentences: what to sweep, then what to
 * answer. A header line holds one of them, and the whole objective there
 * pushed every other word off the row.
 *
 * A line with no full stop is one sentence already, so it comes back whole.
 */
export function firstSentence(s: string): string {
  const text = s.trim();
  const end = text.match(/[.!?](?=\s|$)/);
  return end?.index === undefined ? text : text.slice(0, end.index + 1);
}

/**
 * The line that names a hunt: its objective up to the first line break.
 *
 * A lead hunt's objective is a head sentence over a list of observations. The
 * head sentence names the hunt, and the list stays on the hunt page. An
 * analyst's objective is one line, and it comes back whole. The function
 * never cuts at a character count. A surface that must stay narrow clamps the
 * line with CSS and holds the whole objective in a `title` attribute.
 */
export function objectiveHeadline(objective: string | null | undefined): string {
  const text = (objective ?? '').trim();
  const end = text.search(/\r?\n/);
  return (end === -1 ? text : text.slice(0, end)).trim();
}
