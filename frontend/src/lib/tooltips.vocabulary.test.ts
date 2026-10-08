// Dogfood 2026-10-06, the vocabulary table. Tooltips carried code words: "the
// loop", "fire budget", "precision floor", "candidate", "rule prior", a run
// "class" called "cheap", a stored key such as needs_more_info, and a map
// count printed as "1F · 0H". Each one now reads in the words the console
// uses elsewhere.
import { describe, expect, it } from 'vitest';

import * as TIP from './tooltips';

/** Every exported sentence, flattened: strings, and the strings inside the
 *  exported records. */
function allSentences(): Array<[string, string]> {
  const out: Array<[string, string]> = [];
  for (const [name, value] of Object.entries(TIP)) {
    if (typeof value === 'string') out.push([name, value]);
    else if (value && typeof value === 'object') {
      for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
        if (typeof v === 'string') out.push([`${name}.${k}`, v]);
        else if (v && typeof v === 'object') {
          for (const [k2, v2] of Object.entries(v as Record<string, unknown>)) {
            if (typeof v2 === 'string') out.push([`${name}.${k}.${k2}`, v2]);
          }
        }
      }
    }
  }
  return out;
}

describe('tooltip vocabulary', () => {
  it.each(['fire budget', 'precision floor', 'the loop', 'cheap class'])(
    'no tooltip says "%s"',
    (word) => {
      const hits = allSentences().filter(([, s]) => s.toLowerCase().includes(word));
      expect(hits.map(([n]) => n)).toEqual([]);
    },
  );

  it('no tooltip prints a stored verdict key', () => {
    const hits = allSentences().filter(([, s]) => /\b(true_positive|false_positive|needs_more_info)\b/.test(s));
    expect(hits.map(([n]) => n)).toEqual([]);
  });

  it('names the depth of a run', () => {
    expect(TIP.CHIP_RUN_CLASS.cheap.label).toBe('Depth: quick');
    expect(TIP.CHIP_RUN_CLASS.standard.label).toBe('Depth: standard');
    expect(TIP.CHIP_RUN_CLASS.deep.label).toBe('Depth: deep');
    expect(TIP.CHIP_RUN_CLASS_NONE.label).toBe('Depth: not recorded');
  });

  it('calls the rule prior chip rule history, with the review sentence', () => {
    expect(TIP.CHIP_RUN_CLASS.rule_prior.label).toBe('rule history');
    expect(TIP.CHIP_RUN_CLASS.rule_prior.title).toBe(
      'No model ran. soc-ai copied the latest model verdict of this rule.',
    );
    // Negative control: the Detection tuning column names the setting, and the
    // setting is called "Rule prior" on the Config page. That word stays.
    expect(TIP.RULE_PRIOR_COLUMN).toMatch(/^The rule prior/);
  });

  it('says paused by soc-ai, daily hit limit and minimum precision on a held analytic', () => {
    expect(TIP.CHIP_HELD_BY_SYSTEM).toMatch(/^Paused by soc-ai\./);
    expect(TIP.CHIP_HELD_BY_SYSTEM).toContain('daily hit limit');
    expect(TIP.CHIP_HELD_BY_SYSTEM).toContain('under the minimum');
  });

  it('calls a candidate analytic a draft', () => {
    expect(TIP.CHIP_CANDIDATE).toMatch(/^Draft: /);
  });

  it('explains a departure without the word for itself', () => {
    expect(TIP.OBSERVATION_STATISTIC).toBe(
      'What soc-ai measured, and the usual value for this entity. The gap between the two is the departure.',
    );
    expect(TIP.OBSERVATION_STATISTIC).not.toMatch(/departed/);
  });

  it('names auto-hunt', () => {
    expect(TIP.CHIP_LEFT_TO_YOU).toMatch(/^Auto-hunt starts no hunt here/);
    expect(TIP.ACTION_HUNT_NOW).toBe('Start the hunt now. The lead does not wait for auto-hunt.');
  });

  it('reads the map count in words', () => {
    expect(TIP.mapCountLabel(1, 0)).toBe('1 finding · 0 hosts');
    expect(TIP.mapCountLabel(3, 1)).toBe('3 findings · 1 host');
    // Negative control: the old code form.
    expect(TIP.mapCountLabel(1, 0)).not.toMatch(/\dF|\dH/);
  });

  it('names whose severity a chip shows', () => {
    expect(TIP.severityTitle('High')).toBe(
      'Rule severity: High. The detection rule that raised the alert sets it.',
    );
    expect(TIP.severityTitle('Unknown')).toBe(
      'Rule severity: none. The alert document carries no severity label.',
    );
    expect(TIP.severityTitle('High', 'finding')).toBe('Finding severity: High. The hunt reported it.');
  });

  it('keeps every rewritten sentence free of dashes and under 25 words', () => {
    const rewritten = [
      TIP.CHIP_HELD_BY_SYSTEM,
      TIP.CHIP_CANDIDATE,
      TIP.OBSERVATION_STATISTIC,
      TIP.OBSERVATION_RERUN,
      TIP.CHIP_LEFT_TO_YOU,
      TIP.ACTION_HUNT_NOW,
      TIP.CHIP_RUN_CLASS_NONE.title,
      TIP.CHIP_RUN_CLASS_PENDING.title,
      ...Object.values(TIP.CHIP_RUN_CLASS).map((c) => c.title),
      ...Object.values(TIP.ORACLE_REASON),
    ];
    for (const s of rewritten) {
      expect(s).not.toMatch(/[–—]/);
      for (const sentence of s.split('. ')) expect(sentence.split(/\s+/).length).toBeLessThanOrEqual(25);
    }
  });
});
