// The Rule prior column (stage 1, item 3). Per nominated rule: the alerts the
// rule prior covered, split into two internal addresses and a known external
// address (round prior-b), the real verdicts that agreed and disagreed, and the
// suspension a disagreement leaves, with a Clear button an analyst presses
// after reading the disagreeing run. A rule the prior never covered says why
// it held back on the newest alert, so "not covered" is never a bare blank.
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { DetectionNomination, DetectionTuning } from '../lib/api';
import * as tips from '../lib/tooltips';
import {
  RULE_PRIOR_KNOWN_EXTERNAL,
  RULE_PRIOR_REASON,
  RULE_PRIOR_SUSPENDED,
} from '../lib/tooltips';

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
  // Unmount first. The unmount runs the effects React still owes, and those
  // call the mocks. A reset mock returns undefined and breaks the next tests.
  cleanup();
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

  it('splits the covered alerts into internal and known external addresses', async () => {
    getDetectionTuningMock.mockResolvedValue(
      tuning(
        nomination({
          prior_covered: 9,
          prior_agreements: 8,
          prior_disagreements: 1,
          prior_covered_internal: 6,
          prior_covered_known_external: 3,
          prior_disagreements_internal: 0,
          prior_disagreements_known_external: 1,
        }),
      ),
    );
    render(<DetectionTuningPanel />);
    const internal = await screen.findByTestId(`rule-prior-internal-${RULE}`);
    const external = screen.getByTestId(`rule-prior-external-${RULE}`);
    expect(internal).toHaveTextContent('internal: covered 6 · disagree 0');
    expect(external).toHaveTextContent('known external: covered 3 · disagree 1');
    expect(external).toHaveAttribute('title', RULE_PRIOR_KNOWN_EXTERNAL);
    expect(screen.getByTestId(`rule-prior-${RULE}`)).toHaveTextContent(
      'covered 9 · agree 8 · disagree 1',
    );
  });

  it('shows no split for an older backend', async () => {
    getDetectionTuningMock.mockResolvedValue(
      tuning(nomination({ prior_covered: 4, prior_agreements: 4, prior_disagreements: 0 })),
    );
    render(<DetectionTuningPanel />);
    await screen.findByTestId(`rule-prior-${RULE}`);
    expect(screen.queryByTestId(`rule-prior-internal-${RULE}`)).toBeNull();
    expect(screen.queryByTestId(`rule-prior-external-${RULE}`)).toBeNull();
  });

  it('states the new reasons in words', async () => {
    getDetectionTuningMock.mockResolvedValue(
      tuning(nomination({ prior_covered: 0, prior_last_reason: 'external_endpoint_new' })),
    );
    render(<DetectionTuningPanel />);
    const cell = await screen.findByTestId(`rule-prior-${RULE}`);
    expect(cell).toHaveTextContent(
      'not covered: The external address is new for this rule on this internal machine.',
    );
    expect(RULE_PRIOR_REASON.campaign_machine).toBe(
      'An address belongs to a machine of an open campaign that is not closed.',
    );
  });

  it('never says estate, run or member in a rule prior text', () => {
    const texts = [
      ...Object.values(RULE_PRIOR_REASON),
      tips.RULE_PRIOR_COLUMN,
      tips.RULE_PRIOR_SUSPENDED,
      tips.RULE_PRIOR_UNCHECKED,
      tips.RULE_PRIOR_INTERNAL,
      tips.RULE_PRIOR_KNOWN_EXTERNAL,
    ];
    for (const text of texts) {
      expect(text).not.toMatch(/\b(estate|runs?|members?)\b/i);
      expect(text).not.toMatch(/[–—]/);
    }
  });

  it('writes every reason as one short sentence with no dash', () => {
    for (const text of Object.values(RULE_PRIOR_REASON)) {
      expect(text).not.toMatch(/[–—]/);
      expect(text.split(/\s+/).length).toBeLessThanOrEqual(20);
      expect(text.endsWith('.')).toBe(true);
    }
  });
});
