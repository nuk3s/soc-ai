/**
 * Markdown → plain-text excerpt for one/two-line clamps (runbook list rows).
 * A clamp is no place to render block markdown; showing the raw syntax reads
 * as a bug (dogfood follow-up 2026-07-16). Deliberately regex-simple: strips
 * the common authoring syntax, never throws, keeps all human text.
 */
export function mdToPlainExcerpt(md: string): string {
  return (
    md
      // fences: drop the ``` lines (keep the code text — often the useful bit)
      .replace(/^```[^\n]*$/gm, ' ')
      // headings / blockquotes / list markers at line start
      .replace(/^\s{0,3}(?:#{1,6}\s+|>\s?|[-*+]\s+|\d+\.\s+)/gm, '')
      // links/images: keep the label
      .replace(/!?\[([^\]]*)\]\([^)]*\)/g, '$1')
      // emphasis + inline code markers
      .replace(/(\*\*|__|[*_`~])/g, '')
      .replace(/\s+/g, ' ')
      .trim()
  );
}
