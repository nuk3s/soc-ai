// @vitest-environment node
//
// The owner, 2026-10-07: "'...' is officially forbidden, there are a bunch of
// places where this is present that essentially kills UI and hides
// information."
//
// This test reads every console source file outside the tests and walks its
// string literals, its template text and its JSX text with the TypeScript
// parser. A comment is not a string, so a comment may say "…". A literal that
// holds "…" or "..." fails the test: a loading line says "Loading" beside a
// spinner, and a cut text shows whole and wraps.
//
// The browser draws an ellipsis too. A `truncate`, `text-ellipsis` or
// `line-clamp-*` class, or a `textOverflow: 'ellipsis'` style, cuts the text
// at the box edge and draws "…" there. A class string with one of them fails
// the test the same way.
import ts from 'typescript';
import { describe, expect, it } from 'vitest';

const SOURCES = import.meta.glob<string>(
  ['./**/*.ts', './**/*.tsx', '!./**/*.test.ts', '!./**/*.test.tsx', '!./test/**'],
  { query: '?raw', import: 'default', eager: true },
);

/** Files that another change owns at the time of this test. The count is the
 *  most literals with an ellipsis the file may hold. Drop an entry when that
 *  change lands and the file holds none. */
const OWNED_ELSEWHERE: Record<string, number> = {
  // The graph components. Their SVG labels cut at a character count, and the
  // chart title clamps at two lines.
};

const BANNED = /…|\.\.\./;
/** A class that cuts a text and draws an ellipsis, or the style value. */
const CUT_CLASS =
  /(^|\s)(?:[a-z0-9-]+:)*(truncate|text-ellipsis|overflow-ellipsis|line-clamp-\d+)(?=\s|$)/;
const CUT_STYLE = /^ellipsis$/;

/** The text of each string, template part and JSX text in `source` that holds
 *  an ellipsis or a class that draws one, with its line number. */
export function ellipsisLiterals(fileName: string, source: string): string[] {
  const kind = fileName.endsWith('.tsx') ? ts.ScriptKind.TSX : ts.ScriptKind.TS;
  const file = ts.createSourceFile(fileName, source, ts.ScriptTarget.Latest, true, kind);
  const out: string[] = [];
  const visit = (node: ts.Node) => {
    let text: string | null = null;
    if (
      ts.isStringLiteral(node) ||
      ts.isNoSubstitutionTemplateLiteral(node) ||
      ts.isTemplateHead(node) ||
      ts.isTemplateMiddle(node) ||
      ts.isTemplateTail(node)
    ) {
      text = node.text;
    } else if (ts.isJsxText(node)) {
      text = node.getText(file);
    }
    if (
      text !== null &&
      (BANNED.test(text) || CUT_CLASS.test(text) || CUT_STYLE.test(text.trim()))
    ) {
      const line = file.getLineAndCharacterOfPosition(node.getStart(file)).line + 1;
      out.push(`${fileName}:${line}: ${text.trim().slice(0, 120)}`);
    }
    ts.forEachChild(node, visit);
  };
  visit(file);
  return out;
}

describe('the ellipsis ban', () => {
  it('reads the console source', () => {
    // A glob that matched nothing would pass every check below.
    expect(Object.keys(SOURCES).length).toBeGreaterThan(100);
    expect(Object.keys(SOURCES)).toContain('./screens/Investigations.tsx');
    expect(Object.keys(SOURCES).some((p) => p.includes('.test.'))).toBe(false);
  });

  it('finds no "…", no "..." and no cut class in a string the console renders', () => {
    const found: string[] = [];
    for (const [path, source] of Object.entries(SOURCES)) {
      const hits = ellipsisLiterals(path, source);
      if (hits.length > (OWNED_ELSEWHERE[path] ?? 0)) found.push(...hits);
    }
    expect(found).toEqual([]);
  });

  // Negative controls: the checker catches each form of the cut, and passes a
  // comment, a spread and a regular expression.
  it('catches every place a literal can hold an ellipsis', () => {
    const src = [
      "const a = 'Loading…';",
      'const b = "Saving...";',
      'const c = `Reading ${doc}…`;',
      'const d = `${head}... ${tail}`;',
      "const e = '\\u2026';",
      'const f = <span title="Open…">Starting…</span>;',
      'const g = <span className="min-w-0 truncate">x</span>;',
      "const h = `flex ${wide ? 'xl:line-clamp-1' : ''}`;",
      "const k = { textOverflow: 'ellipsis' };",
      "const m = 'text-ellipsis overflow-hidden';",
    ].join('\n');
    expect(ellipsisLiterals('probe.tsx', src)).toHaveLength(11);
  });

  it('passes a comment, a spread and a regular expression', () => {
    const src = [
      '// Loading… is a comment.',
      '/* "Saving..." is a comment too. */',
      'const g = { ...base, x: [...list] };',
      'const h = /\\.\\.\\.|…/.test(s);',
      'const i = <div {...props}>{/* Reading… */}Ready</div>;',
      "const n = 'The grid truncated the list.';",
      'const o = <span className="break-words whitespace-normal">x</span>;',
    ].join('\n');
    expect(ellipsisLiterals('probe.tsx', src)).toEqual([]);
  });
});
