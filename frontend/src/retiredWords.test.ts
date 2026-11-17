// @vitest-environment node
//
// The owner, 2026-11-14: "Never use the word" for the whole set of machines
// that the console names "the network". And: "'runs' in general make no
// sense ... when presenting artifacts, events, and sequences to the analysts
// we need to think in what they are looking for, not the mechanics of the
// system." The console says "investigation" for an investigation.
//
// This test reads every console source file outside the tests and walks its
// string literals, its template text and its JSX text with the TypeScript
// parser, as noEllipsis.test.ts does. A comment is not a string, so a comment
// may keep the old word. An identifier is not a string either.
//
// The bracket keeps the retired word itself out of the console source.
import ts from 'typescript';
import { describe, expect, it } from 'vitest';
import { statusDetail } from './lib/labels';
import { failureCause, type FailureKind } from './lib/runFailure';

const SOURCES = import.meta.glob<string>(
  ['./**/*.ts', './**/*.tsx', '!./**/*.test.ts', '!./**/*.test.tsx', '!./test/**'],
  { query: '?raw', import: 'default', eager: true },
);

/** The retired word for the whole network, as a word: an identifier such as
 *  `est[a]te_outlier` or `models/est[a]te/` is not a hit. */
const RETIRED = /(?<![\w/-])est[a]tes?(?![\w])/i;

/** "run" or "runs" as a noun: after an article, a determiner or a word that
 *  dates or qualifies it, or after a count at the start of a template part
 *  (`${n} runs`). The verb ("Re-run investigation", "the server still runs
 *  it", "Run now") has none of these in front of it. */
const DETERMINER_RUN =
  /\b(a|an|the|this|that|these|each|every|one|no|some|another|earlier|newer|later|newest|last|new|live|recorded|superseded|failed|deep|finished)\s+runs?\b/i;
const COUNT_RUN = /^ +runs?\b/;
const runNoun = (text: string) => DETERMINER_RUN.test(text) || COUNT_RUN.test(text);
const retired = (text: string) => RETIRED.test(text);

/** The files where every "run" is an investigation. A hunt, a sweep, a
 *  backtest and an evaluation may keep "run" for one execution of that job,
 *  so the files that name those jobs are not on this list. */
const INVESTIGATION_FILES = [
  './screens/Investigation.tsx',
  './screens/Investigations.tsx',
  './screens/Dashboard.tsx',
  './screens/Alerts.tsx',
  './screens/OracleShadowTally.tsx',
  './components/AuthorizedActivityDialog.tsx',
  './components/WaitingActions.tsx',
  './components/DocumentDrawer.tsx',
  './components/Badges.tsx',
  './lib/runFailure.ts',
  './lib/citations.ts',
  './lib/flowSteps.ts',
  './lib/labels.ts',
  './lib/demo.tsx',
];

/** The text of each string, template part and JSX text in `source` that
 *  matches `pattern`, with its line number. */
export function literalsMatching(
  fileName: string,
  source: string,
  matches: (text: string) => boolean,
): string[] {
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
    if (text !== null && matches(text)) {
      const line = file.getLineAndCharacterOfPosition(node.getStart(file)).line + 1;
      out.push(`${fileName}:${line}: ${text.replace(/\s+/g, ' ').trim().slice(0, 120)}`);
    }
    ts.forEachChild(node, visit);
  };
  visit(file);
  return out;
}

describe('the retired words', () => {
  it('reads the console source', () => {
    // A glob that matched nothing would pass every check below.
    expect(Object.keys(SOURCES).length).toBeGreaterThan(100);
    for (const path of INVESTIGATION_FILES) expect(Object.keys(SOURCES)).toContain(path);
    expect(Object.keys(SOURCES).some((p) => p.includes('.test.'))).toBe(false);
  });

  it('finds the retired word for the network in no string the console renders', () => {
    const found = Object.entries(SOURCES).flatMap(([path, source]) =>
      literalsMatching(path, source, retired),
    );
    expect(found).toEqual([]);
  });

  it('finds "run" as a noun for an investigation in no string of an investigation surface', () => {
    const found = INVESTIGATION_FILES.flatMap((path) =>
      literalsMatching(path, SOURCES[path], runNoun),
    );
    expect(found).toEqual([]);
  });

  it('names the subject of a status sentence', () => {
    const statuses = ['complete', 'running', 'queued', 'error', 'cancelled', 'interrupted', 'gone'];
    for (const status of statuses) {
      expect(statusDetail(status)).toMatch(/\binvestigation\b/);
      expect(statusDetail(status, 'hunt')).toMatch(/\bhunt\b/);
      expect(statusDetail(status)).not.toMatch(/\bruns?\b|\{subject\}/);
    }
    const kinds: FailureKind[] = ['gateway', 'token_limit', 'time_limit', 'grid', 'other'];
    for (const kind of kinds) expect(failureCause(kind)).not.toMatch(/\bruns?\b/);
  });

  // Negative controls: the checks catch each form, and pass an identifier, a
  // comment and the verb.
  it('catches the retired word in every place a literal can hold it', () => {
    const word = ['est', 'ate'].join('');
    const src = [
      `const a = 'A change to the ${word} causes it.';`,
      `const b = "${word[0].toUpperCase()}${word.slice(1)}-rare below this many hosts";`,
      `const c = \`\${n} hosts of the ${word}s\`;`,
      `const d = <span title="the ${word} model">the ${word}</span>;`,
      `const e = '${word}_outlier';`,
      `const f = 'models/${word}/';`,
      `const g = 'model-${word}-outlier';`,
      `// the ${word} in a comment`,
    ].join('\n');
    expect(literalsMatching('probe.tsx', src, retired)).toHaveLength(5);
  });

  it('catches "run" as a noun and passes the verb', () => {
    const src = [
      "const a = 'Demo. Some runs are recordings.';",
      "const b = 'A newer run replaced this run.';",
      'const c = <span>recorded run</span>;',
      "const d = `The median of the last ${n} runs is 3 minutes.`;",
      "const e = 'Re-run investigation';",
      "const f = 'The server still runs this investigation.';",
      "const g = 'Bulk Investigate runs';",
      'const h = <button>Run now</button>;',
      "const k = ['run by', who];",
      "const m = 'run-class-chip';",
    ].join('\n');
    expect(literalsMatching('probe.tsx', src, runNoun)).toHaveLength(4);
  });
});
