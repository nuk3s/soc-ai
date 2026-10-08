// One stored word had several screen words. needs_more_info read "Needs info",
// "NMI", "needs_more_info" and "Needs more info" on four screens, a failed hunt
// wore a green chip, and the override select printed snake_case. labels.ts is
// the one map, and these tests hold its words, its colours and its fallbacks.
import { describe, expect, it } from 'vitest';

import {
  CONFIDENCE_HIGH,
  CONFIDENCE_MEDIUM,
  OUTCOME_LABELS,
  STATUS_LABELS,
  TONE,
  VERDICT_LABELS,
  VERDICT_OPTIONS,
  chipProps,
  confidenceMeta,
  confidenceText,
  confidenceWord,
  huntOutcome,
  huntOutcomeText,
  humanize,
  isFailedStatus,
  outcomeLabel,
  outcomeMeta,
  statusDetail,
  statusLabel,
  verdictLabel,
  verdictMeta,
} from './labels';

describe('verdictLabel', () => {
  it('names every verdict in sentence case', () => {
    expect(verdictLabel('true_positive')).toBe('True positive');
    expect(verdictLabel('false_positive')).toBe('False positive');
    expect(verdictLabel('needs_more_info')).toBe('Needs more info');
    expect(verdictLabel('inconclusive')).toBe('Inconclusive');
    expect(verdictLabel('untriaged')).toBe('Untriaged');
  });

  it('gives each verdict the colour the review asked for', () => {
    expect(verdictMeta('true_positive').tone).toBe('danger');
    expect(verdictMeta('false_positive').tone).toBe('muted');
    expect(verdictMeta('needs_more_info').tone).toBe('warn');
    // Negative control: a false positive is not green. Green means a clean
    // hunt, and a sage chip on a false positive read as one.
    expect(verdictMeta('false_positive').tone).not.toBe('ok');
  });

  it('never prints snake_case for a known verdict', () => {
    for (const v of Object.values(VERDICT_LABELS)) expect(v.label).not.toMatch(/_/);
  });

  it('reads an unknown verdict as words and a missing one as No verdict', () => {
    expect(verdictLabel('brand_new_verdict')).toBe('Brand new verdict');
    expect(verdictLabel(null)).toBe('No verdict');
    expect(verdictLabel('')).toBe('No verdict');
  });

  it('offers the three verdicts an analyst can set, in words', () => {
    expect(VERDICT_OPTIONS).toEqual([
      { value: 'true_positive', label: 'True positive' },
      { value: 'false_positive', label: 'False positive' },
      { value: 'needs_more_info', label: 'Needs more info' },
    ]);
  });
});

describe('hunt outcomes', () => {
  it('names every outcome', () => {
    expect(outcomeLabel('threat_found')).toBe('Threat found');
    expect(outcomeLabel('no_threat')).toBe('No threat found');
    expect(outcomeLabel('no_threat_gap')).toBe('No threat found, visibility gap');
    expect(outcomeLabel('no_answer')).toBe('No answer');
    expect(outcomeLabel('could_not_run')).toBe('Could not run');
    expect(outcomeLabel('running')).toBe('Running');
  });

  it('reads the words the hunts API writes today', () => {
    expect(outcomeLabel('threats')).toBe('Threat found');
    expect(outcomeLabel('clean')).toBe('No threat found');
    expect(outcomeLabel('gap')).toBe('No threat found, visibility gap');
    expect(outcomeLabel('failed')).toBe('Could not run');
  });

  it('colours a threat red, a clean hunt green and a gap or a failure grey', () => {
    expect(outcomeMeta('threat_found').tone).toBe('danger');
    expect(outcomeMeta('no_threat').tone).toBe('ok');
    expect(outcomeMeta('no_threat_gap').tone).toBe('muted');
    expect(outcomeMeta('could_not_run').tone).toBe('muted');
    expect(outcomeMeta('no_answer').tone).toBe('warn');
    // Only the clean outcomes are green: the hunt's own clean answer, and the
    // investigations of its findings finding no threat.
    const green = Object.entries(OUTCOME_LABELS).filter(([, m]) => m.tone === 'ok');
    expect(green.map(([k]) => k)).toEqual(['no_threat', 'no_threat_confirmed']);
  });

  it('names the outcomes of the investigation phase with their counts', () => {
    expect(outcomeLabel('investigating', { investigated: 2, total: 3 })).toBe(
      'Investigating 2 of 3 findings',
    );
    expect(outcomeLabel('threats_confirmed', { threats: 2, total: 3 })).toBe(
      '2 of 3 findings are threats',
    );
    expect(outcomeLabel('threats_confirmed', { threats: 1, total: 1 })).toBe(
      '1 of 1 finding is a threat',
    );
    expect(outcomeLabel('no_threat_confirmed')).toBe('No threat confirmed');
    // Without counts each reads its plain label.
    expect(outcomeLabel('investigating')).toBe('Investigating findings');
    expect(outcomeLabel('threats_confirmed')).toBe('Threats confirmed');
    expect(outcomeMeta('threats_confirmed').tone).toBe('danger');
    expect(outcomeMeta('investigating').tone).toBe('info');
  });

  it('reads an investigating hunt as investigating, never as stopped', () => {
    expect(huntOutcome({ status: 'investigating', outcome: 'threat_found' })).toBe('investigating');
    expect(huntOutcome({ status: 'complete', outcome: 'threats_confirmed' })).toBe(
      'threats_confirmed',
    );
    expect(huntOutcome({ status: 'complete', outcome: 'no_threat_confirmed' })).toBe(
      'no_threat_confirmed',
    );
  });

  it('writes the outcome text of a hunt row', () => {
    // The server's words win: only the server counts the true positives.
    expect(
      huntOutcomeText({
        status: 'complete',
        outcome: 'threats_confirmed',
        outcome_label: '2 of 3 findings are threats',
      }),
    ).toBe('2 of 3 findings are threats');
    // An older server sends no label. The row's counts write the progress.
    expect(
      huntOutcomeText({ status: 'investigating', findingsInvestigated: 1, findingsTotal: 4 }),
    ).toBe('Investigating 1 of 4 findings');
    // Control: a stopped hunt reads its stop, whatever label the row holds.
    expect(huntOutcomeText({ status: 'error', outcome_label: 'Threat found' })).toBe(
      'Could not run',
    );
    expect(huntOutcomeText({ status: 'complete' })).toBeNull();
  });

  it('reads a stopped hunt as Could not run whatever its outcome field says', () => {
    for (const status of ['error', 'cancelled', 'interrupted']) {
      expect(huntOutcome({ status, outcome: 'clean' })).toBe('could_not_run');
    }
    expect(huntOutcome({ status: 'running' })).toBe('running');
    expect(huntOutcome({ status: 'complete', outcome: 'failed' })).toBe('could_not_run');
    expect(huntOutcome({ status: 'complete', outcome: 'gap' })).toBe('no_threat_gap');
    expect(huntOutcome({ status: 'complete', outcome: 'threats' })).toBe('threat_found');
    // Negative control: a complete clean hunt is not a failure.
    expect(huntOutcome({ status: 'complete', outcome: 'clean' })).toBe('no_threat');
  });

  it('returns null for a complete row that names no outcome', () => {
    expect(huntOutcome({ status: 'complete', outcome: '' })).toBeNull();
    expect(huntOutcome({ status: 'complete' })).toBeNull();
  });

  it('reads an unknown outcome as words, in grey', () => {
    expect(outcomeLabel('partly_done')).toBe('Partly done');
    expect(outcomeMeta('partly_done').tone).toBe('muted');
  });
});

describe('run statuses', () => {
  it('reads error, cancelled and interrupted as Failed', () => {
    expect(statusLabel('error')).toBe('Failed');
    expect(statusLabel('cancelled')).toBe('Failed');
    expect(statusLabel('interrupted')).toBe('Failed');
    expect(isFailedStatus('interrupted')).toBe(true);
  });

  it('keeps the cause for the tooltip', () => {
    expect(statusDetail('cancelled')).toMatch(/cancel request/);
    expect(statusDetail('interrupted')).toMatch(/service restart/);
    expect(statusDetail('error')).toMatch(/error/);
  });

  it('does not call a finished or running run Failed', () => {
    expect(statusLabel('complete')).toBe('Complete');
    expect(statusLabel('running')).toBe('Running');
    expect(isFailedStatus('complete')).toBe(false);
    expect(isFailedStatus(null)).toBe(false);
  });

  it('never colours a failure green', () => {
    for (const s of ['error', 'cancelled', 'interrupted'] as const) {
      expect(STATUS_LABELS[s].tone).not.toBe('ok');
    }
  });
});

describe('chipProps', () => {
  it('carries the tone class and the tone name', () => {
    const p = chipProps(verdictMeta('true_positive'));
    expect(p.className).toContain(TONE.danger.chipClass);
    expect(p['data-tone']).toBe('danger');
    expect(p.title).toBeUndefined();
  });

  it('sizes a header chip apart from a list chip and passes a title', () => {
    const lg = chipProps(outcomeMeta('could_not_run'), { size: 'lg', title: 'why' });
    expect(lg.className).toContain('uppercase');
    expect(lg.title).toBe('why');
    expect(chipProps(outcomeMeta('could_not_run')).className).not.toContain('uppercase');
  });

  it('builds every chip class from whole literal Tailwind names', () => {
    // Tailwind reads the source for class names. A name built at runtime
    // would have no CSS behind it.
    for (const t of Object.values(TONE)) {
      expect(t.chipClass.split(' ')).toHaveLength(3);
      expect(t.chipClass).not.toMatch(/\$\{/);
    }
  });
});

describe('confidence', () => {
  it('prints two decimals', () => {
    expect(confidenceText(0.7)).toBe('0.70');
    expect(confidenceText(0.855)).toBe('0.85');
    expect(confidenceText(1)).toBe('1.00');
    expect(confidenceText(null)).toBe('Not recorded');
    expect(confidenceText(undefined, '')).toBe('');
  });

  it('names the band the server acts on', () => {
    expect(CONFIDENCE_HIGH).toBe(0.8);
    expect(CONFIDENCE_MEDIUM).toBe(0.7);
    expect(confidenceWord(0.95)).toBe('High');
    expect(confidenceWord(0.8)).toBe('High');
    expect(confidenceWord(0.79)).toBe('Medium');
    expect(confidenceWord(0.7)).toBe('Medium');
    expect(confidenceWord(0.69)).toBe('Low');
    expect(confidenceWord(0.4)).toBe('Low');
  });

  it('agrees with the two decimals printed beside it', () => {
    // 0.699 prints as 0.70, so the word beside it must be Medium too.
    expect(confidenceText(0.699)).toBe('0.70');
    expect(confidenceWord(0.699)).toBe('Medium');
    // Negative control: 0.694 prints as 0.69 and stays Low.
    expect(confidenceWord(0.694)).toBe('Low');
  });

  it('never colours high confidence green', () => {
    expect(confidenceMeta(0.9).tone).not.toBe('ok');
    expect(confidenceMeta(0.5).tone).toBe('warn');
  });
});

describe('humanize', () => {
  it('turns a key into words', () => {
    expect(humanize('could_not_run')).toBe('Could not run');
    expect(humanize('')).toBe('');
  });
});
