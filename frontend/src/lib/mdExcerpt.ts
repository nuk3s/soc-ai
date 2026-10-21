/**
 * Markdown → plain-text excerpt for one/two-line clamps (runbook list rows).
 * A clamp is no place to render block markdown; showing the raw syntax reads
 * as a bug (dogfood follow-up 2026-07-16). Deliberately regex-simple: strips
 * the common authoring syntax, never throws, keeps all human text.
 *
 * Only a REAL emphasis marker goes. The strip used to remove every `_`, `*`
 * and `~`, so the file name "mpam-d_bd_*.exe" read "mpam-dbd.exe" (dogfood
 * 2026-10-19, R5-D15). A marker counts as emphasis the way CommonMark counts
 * it, near enough for an excerpt: a pair that opens before a non-space and
 * closes after one, and for `_` only at a word edge. The text of inline code
 * and an escaped character stay as written.
 */

// Text the emphasis passes must not touch: inline code and escaped
// characters. Each is swapped for a private-use token and put back at the end.
const KEEP_OPEN = '\uE000';
const KEEP_CLOSE = '\uE001';
const KEEP_TOKEN = new RegExp(`${KEEP_OPEN}(\\d+)${KEEP_CLOSE}`, 'g');

export function mdToPlainExcerpt(md: string): string {
  const kept: string[] = [];
  const keep = (text: string): string => {
    kept.push(text);
    return `${KEEP_OPEN}${kept.length - 1}${KEEP_CLOSE}`;
  };
  return (
    md
      // fences: drop the ``` lines (keep the code text — often the useful bit)
      .replace(/^```[^\n]*$/gm, ' ')
      // inline code: the text between the backticks, as written
      .replace(/`([^`\n]+)`/g, (_m, code: string) => keep(code))
      // a backslash escape is the literal character
      .replace(/\\([\\`*_~[\]()#+\-.!>|{}])/g, (_m, ch: string) => keep(ch))
      // headings / blockquotes / list markers at line start
      .replace(/^\s{0,3}(?:#{1,6}\s+|>\s?|[-*+]\s+|\d+\.\s+)/gm, '')
      // links/images: keep the label
      .replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1')
      // strong and strike: ** anywhere, __ and ~~ as a pair
      .replace(/\*\*(?=\S)([^\n]*?\S)\*\*/g, '$1')
      .replace(/(^|[^\w])__(?=\S)([^\n]*?\S)__(?!\w)/g, '$1$2')
      .replace(/~~(?=\S)([^\n]*?\S)~~/g, '$1')
      // emphasis: * may sit inside a word, _ only at a word edge
      .replace(/\*(?=[^\s*])([^*\n]*?[^\s*])\*/g, '$1')
      .replace(/(^|[^\w])_(?=[^\s_])([^\n]*?[^\s_])_(?!\w)/g, '$1$2')
      .replace(KEEP_TOKEN, (_m, i: string) => kept[Number(i)] ?? '')
      .replace(/\s+/g, ' ')
      .trim()
  );
}
