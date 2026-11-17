// L3 (review 2026-11-12): the panel showed "37 · 25 MUTE SUGGESTIONS", one red
// Mute badge for each row and no line that said what the 25 cost. It now
// states one next step above the table, with one control for those rules.
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { DetectionNomination, DetectionTuning } from '../lib/api';

const getDetectionTuningMock = vi.hoisted(() => vi.fn());
const muteRuleMock = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getDetectionTuning: getDetectionTuningMock,
  muteRule: muteRuleMock,
}));

import { DetectionTuningPanel, muteCandidates, nextStepSentence } from './DetectionTuningPanel';

function rule(name: string, over: Partial<DetectionNomination> = {}): DetectionNomination {
  return {
    rule_name: name,
    alert_count: 1000,
    investigations: 10,
    fp: 10,
    tp: 0,
    nmi: 0,
    recommendation: 'mute',
    reason: 'all false positive',
    already_muted: false,
    override_fp: 0,
    chat_resolved: 0,
    manual_resolved: 0,
    ...over,
  };
}

const TUNING: DetectionTuning = {
  nominations: [
    rule('ET NOISE A', { alert_count: 6000 }),
    rule('ET NOISE B', { alert_count: 4000 }),
    // Controls: a rule that caught a true positive, a muted rule and a
    // monitor are no part of the next step.
    rule('ET SCAN Nmap', { tp: 1, recommendation: 'none' }),
    rule('ET MUTED', { already_muted: true }),
    rule('ET WATCH', { recommendation: 'monitor' }),
  ],
  overrides: [],
  window: '7d',
  alert_total: 17062,
};

afterEach(() => {
  cleanup();
  getDetectionTuningMock.mockReset();
  muteRuleMock.mockReset();
});

describe('DetectionTuningPanel next step', () => {
  it('states the share of the window and offers one control for those rules', async () => {
    getDetectionTuningMock.mockResolvedValue(TUNING);
    muteRuleMock.mockResolvedValue({});
    render(<DetectionTuningPanel />);
    const line = await screen.findByTestId('tuning-next-step');
    expect(line.textContent).toContain('2 rules produce 59% of the alert events of the last 7 days and no true positive.');
    fireEvent.click(screen.getByTestId('tuning-mute-all'));
    expect(screen.getByTestId('tuning-mute-confirm').textContent).toContain('Mute 2 rules?');
    expect(muteRuleMock).not.toHaveBeenCalled();
    fireEvent.click(screen.getByTestId('tuning-mute-all-confirm'));
    await waitFor(() => expect(muteRuleMock).toHaveBeenCalledTimes(2));
    expect(muteRuleMock.mock.calls.map((c) => c[0])).toEqual(['ET NOISE A', 'ET NOISE B']);
  });

  it('paints no mute in red', async () => {
    getDetectionTuningMock.mockResolvedValue(TUNING);
    const { container } = render(<DetectionTuningPanel />);
    await screen.findByTestId('tuning-next-step');
    expect(container.innerHTML).not.toMatch(/#f04438|rgb\(240, 68, 56\)|text-danger/);
  });

  it('counts the events when the grid gave no total, and shows nothing with no candidate', () => {
    expect(nextStepSentence(TUNING.nominations, null, '7d')).toBe(
      '2 rules produce 10,000 alert events of the last 7 days and no true positive.',
    );
    // NEGATIVE CONTROL: a rule with a true positive never joins the step.
    expect(muteCandidates([rule('ET TP', { tp: 1 })])).toEqual([]);
    expect(nextStepSentence([rule('ET TP', { tp: 1 })], 100, '7d')).toBeNull();
  });
});
