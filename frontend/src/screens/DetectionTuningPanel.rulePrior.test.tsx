// The Rule prior column (stage 1, item 3). Per nominated rule: the alerts the
// rule prior covered, the real verdicts that agreed and disagreed, and the
// suspension a disagreement leaves, with a Clear button an analyst presses
// after reading the disagreeing run. A rule the prior never covered says why
// it held back on the newest alert, so "not covered" is never a bare blank.
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { DetectionNomination, DetectionTuning } from '../lib/api';
import { RULE_PRIOR_REASON, RULE_PRIOR_SUSPENDED } from '../lib/tooltips';

const getDetectionTuningMock = vi.hoisted(() => vi.fn());
const clearRulePriorMock = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getDetectionTuning: getDetectionTuningMock,
  clearRulePrior: clearRulePriorMock,
}));

import { DetectionTuningPanel } from './DetectionTuningPanel';

const RULE = 'ET INFO STUN Binding Request';

const nomination = (over: Partial<DetectionNomination>): DetectionNomination => ({
  rule_name: RULE,
  alert_count: 420,
  investigations: 40,
  fp: 40,
  tp: 0,
  nmi: 0,
  recommendation: 'mute',
  reason: '420 alerts, 40 investigated, all false positive',
  already_muted: false,
  override_fp: 0,
  chat_resolved: 0,
  manual_resolved: 0,
  ...over,
});

const tuning = (n: DetectionNomination): DetectionTuning => ({ nominations: [n], overrides: [] });

afterEach(() => {
  getDetectionTuningMock.mockReset();
  clearRulePriorMock.mockReset();
});

describe('DetectionTuningPanel: Rule prior column', () => {
  it('names the column', async () => {
    getDetectionTuningMock.mockResolvedValue(tuning(nomination({})));
    render(<DetectionTuningPanel />);
    expect(await screen.findByText('Rule prior')).toBeTruthy();
  });

  it('counts covered alerts, agreements and disagreements', async () => {
    getDetectionTuningMock.mockResolvedValue(
      tuning(
        nomination({
          prior_covered: 31,
          prior_agreements: 30,
          prior_disagreements: 1,
          prior_unchecked: 0,
          prior_suspended: false,
        }),
      ),
    );
    render(<DetectionTuningPanel />);
    const cell = await screen.findByTestId(`rule-prior-${RULE}`);
    expect(cell).toHaveTextContent('covered 31 · agree 30 · disagree 1');
    expect(screen.queryByText('Suspended')).toBeNull();
  });

  it('shows the suspension and clears it on request', async () => {
    getDetectionTuningMock.mockResolvedValue(
      tuning(
        nomination({
          prior_covered: 12,
          prior_agreements: 11,
          prior_disagreements: 1,
          prior_suspended: true,
        }),
      ),
    );
    clearRulePriorMock.mockResolvedValue({ rule_name: RULE, cleared: 1 });
    render(<DetectionTuningPanel />);
    const chip = await screen.findByText('Suspended');
    expect(chip).toHaveAttribute('title', RULE_PRIOR_SUSPENDED);
    fireEvent.click(screen.getByRole('button', { name: 'Clear' }));
    await waitFor(() => expect(clearRulePriorMock).toHaveBeenCalledWith(RULE));
    // The panel reloads after the clearance lands.
    await waitFor(() => expect(getDetectionTuningMock).toHaveBeenCalledTimes(2));
  });

  it('says why the prior held back when it covered nothing', async () => {
    getDetectionTuningMock.mockResolvedValue(
      tuning(nomination({ prior_covered: 0, prior_last_reason: 'analyst_override' })),
    );
    render(<DetectionTuningPanel />);
    const cell = await screen.findByTestId(`rule-prior-${RULE}`);
    expect(cell).toHaveTextContent(`not covered: ${RULE_PRIOR_REASON.analyst_override}`);
    expect(screen.queryByRole('button', { name: 'Clear' })).toBeNull();
  });

  it('reads an older backend with no rule prior fields as not covered', async () => {
    getDetectionTuningMock.mockResolvedValue(tuning(nomination({})));
    render(<DetectionTuningPanel />);
    const cell = await screen.findByTestId(`rule-prior-${RULE}`);
    expect(cell).toHaveTextContent('not covered');
  });

  it('writes every reason as one short sentence with no dash', () => {
    for (const text of Object.values(RULE_PRIOR_REASON)) {
      expect(text).not.toMatch(/[–—]/);
      expect(text.split(/\s+/).length).toBeLessThanOrEqual(20);
      expect(text.endsWith('.')).toBe(true);
    }
  });
});
