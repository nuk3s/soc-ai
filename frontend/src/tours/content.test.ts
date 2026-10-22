// The mechanical half of the writing standard for the tour text. The other
// half (one topic per sentence, active voice, the product terms) needs a
// reader: the owner reviews content.ts, and the avoid-ai-writing skill runs
// over it in detect mode before a commit.
import { describe, expect, it } from 'vitest';
import { ALL_TOURS, PAGE_TOURS, WELCOME_TOUR, pageTourFor, tourById } from './content';
import type { Tour } from './types';

const BANNED: RegExp[] = [
  /\bsimply\b/i,
  /\bjust\b/i,
  /\beas(y|ily)\b/i,
  /\bpowerful\b/i,
  /\bseamless(ly)?\b/i,
  /\bsilently\b/i,
  /\bquietly\b/i,
  /\bhonest(ly)?\b/i,
  /\brather than\b/i,
  /\binstead of\b/i,
  /\bnot merely\b/i,
  /\bnot only\b/i,
  /\bkinds?\b/i,
  /\bwelcome aboard\b/i,
  /\blet's\b/i,
  /\byou're\b/i,
  /\byou've\b/i,
  /\byou'll\b/i,
  /\ball set\b/i,
  /\bawesome\b/i,
  /\bleverage\b/i,
  /\butilize\b/i,
  /\bunlock\b/i,
  /\bseamless\b/i,
  /\bjourney\b/i,
  /\beffortless(ly)?\b/i,
  /\brobust\b/i,
  /\bConfig page\b/,
  /\bOperate page\b/,
];

// The first word of an imperative sentence: such a sentence is an
// instruction, and STE caps it at 20 words.
const IMPERATIVE = new Set([
  'press', 'open', 'click', 'select', 'use', 'read', 'pick', 'type', 'choose', 'set', 'turn',
  'drag', 'filter', 'sort', 'expand', 'hover', 'follow', 'save', 'check', 'ask', 'start', 'run',
  'show', 'find', 'add', 'mark', 'dismiss', 'review', 'go', 'jump', 'see', 'keep', 'enter',
  'change', 'move', 'apply', 'cancel', 'decide', 'hunt', 'acknowledge', 'escalate', 'write',
]);

function sentences(body: string): string[] {
  // A sentence ends at a period, then a space or the end. Abbreviations are
  // not part of the tour vocabulary.
  return body
    .split(/(?<=\.)\s+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function words(s: string): number {
  return s.split(/\s+/).filter(Boolean).length;
}

function textProblems(text: string): string[] {
  const out: string[] = [];
  if (/[—–]/.test(text)) out.push('em or en dash');
  if (/[!]/.test(text)) out.push('exclamation mark');
  if (/[()]/.test(text)) out.push('parenthesis');
  if (/;/.test(text)) out.push('semicolon');
  if (/\s-\s/.test(text)) out.push('spaced hyphen used as a dash');
  if (/\bnot\b[^.]*\bbut\b/i.test(text)) out.push('"not X but Y"');
  for (const re of BANNED) if (re.test(text)) out.push(`banned word ${re}`);
  return out;
}

function tourProblems(tour: Tour): string[] {
  const out: string[] = [];
  const anchors = new Set<string>();
  for (const [i, step] of tour.steps.entries()) {
    const at = `step ${i + 1} (${step.anchor})`;
    if (!/^[a-z0-9][a-z0-9-]*$/.test(step.anchor)) out.push(`${at}: anchor is not lowercase with hyphens`);
    if (anchors.has(step.anchor)) out.push(`${at}: anchor used twice`);
    anchors.add(step.anchor);
    const t = step.title;
    if (!t.trim()) out.push(`${at}: empty title`);
    if (words(t) > 5) out.push(`${at}: title longer than 5 words`);
    if (/[.?:]$/.test(t)) out.push(`${at}: title ends in punctuation`);
    if (!/^[A-Z⌘0-9]/.test(t)) out.push(`${at}: title does not start with a capital`);
    for (const p of textProblems(t)) out.push(`${at}: title: ${p}`);
    const ss = sentences(step.body);
    if (ss.length < 1 || ss.length > 3) out.push(`${at}: body has ${ss.length} sentences, 1 to 3 allowed`);
    for (const s of ss) {
      if (!s.endsWith('.')) out.push(`${at}: sentence does not end with a period: "${s}"`);
      const first = s.split(/\s+/, 1)[0].toLowerCase();
      const cap = IMPERATIVE.has(first) ? 20 : 25;
      if (words(s) > cap) out.push(`${at}: ${words(s)} words, cap ${cap}: "${s}"`);
    }
    for (const p of textProblems(step.body)) out.push(`${at}: body: ${p}`);
  }
  return out;
}

describe('tour content', () => {
  it('gives every tour a unique id and a positive version', () => {
    const ids = ALL_TOURS.map((t) => t.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const t of ALL_TOURS) {
      expect(t.id).toMatch(/^[a-z][a-z0-9-]{0,47}$/);
      expect(Number.isInteger(t.version) && t.version >= 1).toBe(true);
      expect(tourById(t.id)).toBe(t);
    }
  });

  it('keeps the welcome tour to six steps over the shell', () => {
    expect(WELCOME_TOUR.steps.length).toBeGreaterThan(0);
    expect(WELCOME_TOUR.steps.length).toBeLessThanOrEqual(6);
    expect(WELCOME_TOUR.routes).toEqual([]);
    expect(tourProblems(WELCOME_TOUR)).toEqual([]);
  });

  it.each(PAGE_TOURS.map((t) => [t.id, t] as const))('tour %s: 3 to 7 steps in STE', (_id, tour) => {
    expect(tour.steps.length).toBeGreaterThanOrEqual(3);
    expect(tour.steps.length).toBeLessThanOrEqual(7);
    expect(tour.routes.length).toBeGreaterThan(0);
    expect(tourProblems(tour)).toEqual([]);
  });

  it('maps every in-shell route to its page tour', () => {
    const cases: [string, string][] = [
      ['/dashboard', 'dashboard'],
      ['/alerts', 'alerts'],
      ['/investigations', 'investigations'],
      ['/investigation/01J0000000000000000000000', 'investigation'],
      ['/hunts', 'hunts'],
      ['/hunts/01J0000000000000000000000', 'hunt'],
      ['/leads/17', 'lead'],
      ['/hosts', 'hosts'],
      ['/hosts/192.0.2.10', 'host'],
      ['/entity/alice', 'entity'],
      ['/config', 'settings'],
      ['/operate', 'status'],
      ['/backtest', 'backtest'],
      ['/runbooks', 'runbooks'],
      ['/notifications', 'notifications'],
    ];
    for (const [path, id] of cases) expect(pageTourFor(path)?.id, path).toBe(id);
    expect(pageTourFor('/no-such-page')).toBeUndefined();
  });

  it('catches the faults it names', () => {
    const bad: Tour = {
      id: 'bad',
      version: 1,
      name: 'Bad',
      routes: ['/bad'],
      steps: [
        { anchor: 'Bad_Anchor', title: 'a title.', body: 'Simply press it — now!' },
        {
          anchor: 'two',
          title: 'Two',
          body: 'Press the button and then press the other button and then read every one of the many rows in the list.',
        },
      ],
    };
    const problems = tourProblems(bad).join('\n');
    for (const want of ['lowercase', 'punctuation', 'capital', 'em or en dash', 'exclamation', 'banned word', 'cap 20']) {
      expect(problems).toContain(want);
    }
  });
});
