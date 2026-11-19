// The decision bar of the rule page (round 3, RC3). Each button states what
// it writes before the press. After the press the bar states the progress and
// then the result. A failed result states the failure and keeps the buttons.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { RuleDecision } from '../../screens/RuleDecision';

vi.mock('../../lib/api', async () => {
  const actual = await vi.importActual<typeof import('../../lib/api')>('../../lib/api');
  return { ...actual, getRuleDecision: vi.fn(), postRuleDecision: vi.fn(), endRuleDecision: vi.fn() };
});
import {
  ApiError,
  endRuleDecision,
  getRuleDecision,
  postRuleDecision,
  type RuleDecisionRecord,
} from '../../lib/api';
import { forbiddenWords } from '../../test/analystWords';
import { RULE_KEY, ruleDetail } from '../../test/ruleDecision';

const RECORD: RuleDecisionRecord = {
  id: 9,
  decision: 'acknowledge',
  by: 'ana',
  at: '2026-11-14T12:00:00Z',
  note: 'Vendor update traffic.',
  state: 'acknowledging',
  alerts: null,
  failed: null,
  endedAt: null,
  endCause: null,
};

function mount() {
  return render(
    <MemoryRouter initialEntries={[`/needs-you/rule/${RULE_KEY}`]}>
      <Routes>
        <Route path="/needs-you/rule/:ruleKey" element={<RuleDecision />} />
      </Routes>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.mocked(getRuleDecision).mockReset().mockResolvedValue(ruleDetail());
  vi.mocked(postRuleDecision).mockReset().mockResolvedValue(RECORD);
  vi.mocked(endRuleDecision).mockReset();
});

describe('RuleDecisionBar', () => {
  it('states what the main button writes before the press, with the weak ones off', async () => {
    mount();
    const main = await screen.findByTestId('rule-acknowledge');
    expect(main).toHaveTextContent('Acknowledge the 470 false positives with checked evidence');
    expect(screen.getByTestId('rule-acknowledge-writes')).toHaveTextContent(
      'Writes: soc-ai acknowledges the alerts of 470 investigations and the alerts that inherit their verdict in Security Onion.',
    );
    const box = screen.getByTestId('rule-include-weak') as HTMLInputElement;
    expect(box.checked).toBe(false);
    expect(box.closest('label')).toHaveTextContent('Also the 1 with weak evidence');
    // The second choice states what stays guarded.
    expect(screen.getByTestId('rule-standing-choice')).toHaveTextContent(
      'Acknowledge these, and each later false positive of this rule for 30 days',
    );
    expect(screen.getByTestId('rule-standing-writes')).toHaveTextContent(
      'A later verdict with weak evidence still waits for you. A true positive verdict on the rule ends the decision.',
    );
  });

  it('names the whole count when the analyst adds the weak ones', async () => {
    mount();
    fireEvent.click(await screen.findByTestId('rule-include-weak'));
    expect(screen.getByTestId('rule-acknowledge')).toHaveTextContent('Acknowledge the 471 false positives');
    expect(screen.getByTestId('rule-acknowledge-writes')).toHaveTextContent('the alerts of 471 investigations');
    fireEvent.click(screen.getByTestId('rule-acknowledge'));
    await waitFor(() =>
      expect(postRuleDecision).toHaveBeenCalledWith(RULE_KEY, { decision: 'acknowledge', includeWeak: true, note: '' }),
    );
  });

  it('states the progress after the press and then the result', async () => {
    vi.mocked(getRuleDecision)
      .mockResolvedValueOnce(ruleDetail())
      .mockResolvedValueOnce(ruleDetail({ history: [{ ...RECORD, alerts: 300 }] }))
      .mockResolvedValue(
        ruleDetail({
          confident: { ...ruleDetail().confident, count: 0, reasons: [] },
          history: [{ ...RECORD, state: 'done', alerts: 1204, failed: 0 }],
        }),
      );
    mount();
    fireEvent.change(await screen.findByTestId('rule-note'), { target: { value: ' Vendor update traffic. ' } });
    fireEvent.click(screen.getByTestId('rule-acknowledge'));
    await waitFor(() =>
      expect(postRuleDecision).toHaveBeenCalledWith(RULE_KEY, {
        decision: 'acknowledge',
        includeWeak: false,
        note: 'Vendor update traffic.',
      }),
    );
    const result = await screen.findByTestId('rule-decision-result');
    await waitFor(() => expect(result).toHaveTextContent('soc-ai acknowledges the alerts in Security Onion.'));
    // The buttons wait while soc-ai writes.
    expect(screen.getByTestId('rule-acknowledge')).toBeDisabled();
    await waitFor(
      () => expect(screen.getByTestId('rule-decision-result')).toHaveTextContent('Acknowledged 1,204 alerts. 0 failed.'),
      { timeout: 8000 },
    );
    expect(screen.getByTestId('rule-decision-result')).toHaveAttribute('data-state', 'done');
    expect(screen.getByTestId('rule-history')).toHaveTextContent('ana acknowledged the false positives at 2026-11-14 12:00 UTC.');
  });

  // NEGATIVE CONTROL: a failed result states the failure and keeps the buttons.
  it('states a failed result and keeps the buttons', async () => {
    vi.mocked(postRuleDecision).mockResolvedValue({ ...RECORD, state: 'failed', alerts: 0, failed: 12 });
    vi.mocked(getRuleDecision)
      .mockResolvedValueOnce(ruleDetail())
      .mockResolvedValue(ruleDetail({ history: [{ ...RECORD, state: 'failed', alerts: 0, failed: 12 }] }));
    mount();
    fireEvent.click(await screen.findByTestId('rule-acknowledge'));
    const result = await screen.findByTestId('rule-decision-result');
    await waitFor(() => expect(result).toHaveAttribute('data-state', 'failed'));
    expect(within(result).getByRole('alert')).toHaveTextContent(
      'The decision failed. Acknowledged 0 alerts. 12 failed. Press a button to try again.',
    );
    await waitFor(() => expect(screen.getByTestId('rule-acknowledge')).toBeEnabled());
    expect(screen.getByTestId('rule-standing-choice')).toBeEnabled();
  });

  // NEGATIVE CONTROL: a refused write states the reason and keeps the buttons.
  it('states the reason of a refused write and keeps the buttons', async () => {
    vi.mocked(postRuleDecision).mockRejectedValue(
      new ApiError('The rule holds a standing true positive verdict.', 409, 'rule_has_true_positive'),
    );
    mount();
    fireEvent.click(await screen.findByTestId('rule-standing-choice'));
    expect(await screen.findByTestId('rule-decision-error')).toHaveTextContent(
      'The rule holds a standing true positive verdict.',
    );
    expect(postRuleDecision).toHaveBeenCalledWith(RULE_KEY, { decision: 'standing', includeWeak: false, note: '' });
    expect(screen.getByTestId('rule-acknowledge')).toBeEnabled();
    expect(screen.queryByTestId('rule-decision-result')).toBeNull();
  });

  it('states the progress of a decision that soc-ai still writes after a reload, and holds the buttons', async () => {
    vi.mocked(getRuleDecision).mockResolvedValue(ruleDetail({ history: [{ ...RECORD, alerts: 40 }] }));
    mount();
    const result = await screen.findByTestId('rule-decision-result');
    expect(result).toHaveTextContent('soc-ai acknowledges the alerts in Security Onion. 40 acknowledged so far.');
    expect(screen.getByTestId('rule-acknowledge')).toBeDisabled();
  });

  // NEGATIVE CONTROL: a rule with 0 weak shows no check box.
  it('shows no check box for a rule with no weak evidence', async () => {
    vi.mocked(getRuleDecision).mockResolvedValue(
      ruleDetail({ weak: { count: 0, reasons: [], sources: 0, destinations: 0, firstEvent: null, lastEvent: null } }),
    );
    mount();
    expect(await screen.findByTestId('rule-acknowledge')).toHaveTextContent('Acknowledge the 470 false positives with checked evidence');
    expect(screen.queryByTestId('rule-include-weak')).toBeNull();
  });

  // NEGATIVE CONTROL: canStanding false hides the second choice and states why.
  it('hides the second choice with the reason when the server refuses it', async () => {
    vi.mocked(getRuleDecision).mockResolvedValue(
      ruleDetail({ canStanding: false, canStandingWhy: 'The rule holds a standing true positive verdict.' }),
    );
    mount();
    expect(await screen.findByTestId('rule-standing-refused')).toHaveTextContent(
      'soc-ai offers no standing decision for this rule. The rule holds a standing true positive verdict.',
    );
    expect(screen.queryByTestId('rule-standing-choice')).toBeNull();
    expect(screen.getByTestId('rule-acknowledge')).toBeEnabled();
  });

  it('shows a standing decision in force with its end date, its count and the end button', async () => {
    vi.mocked(getRuleDecision)
      .mockResolvedValueOnce(
        ruleDetail({
          standing: { id: 4, by: 'ana', at: '2026-11-10T08:00:00Z', endsAt: '2026-12-10T08:00:00Z', acknowledged: 37 },
        }),
      )
      .mockResolvedValue(ruleDetail());
    vi.mocked(endRuleDecision).mockResolvedValue({ ...RECORD, decision: 'standing', state: 'done', endedAt: '2026-11-14T12:00:00Z', endCause: 'analyst' });
    mount();
    const standing = await screen.findByTestId('rule-standing');
    expect(standing).toHaveTextContent(
      'A standing decision is in force until 2026-12-10 08:00 UTC. ana made it at 2026-11-10 08:00 UTC. soc-ai acknowledged 37 later false positives under it.',
    );
    expect(screen.getByTestId('rule-end-writes')).toHaveTextContent(
      'Writes: soc-ai ends the standing decision. Each later false positive of this rule waits for you again.',
    );
    // A decision in force offers no second standing decision, and no refusal.
    expect(screen.queryByTestId('rule-standing-choice')).toBeNull();
    expect(screen.queryByTestId('rule-standing-refused')).toBeNull();
    fireEvent.click(within(standing).getByRole('button', { name: 'End the standing decision' }));
    await waitFor(() => expect(endRuleDecision).toHaveBeenCalledWith(RULE_KEY));
    await waitFor(() => expect(screen.queryByTestId('rule-standing')).toBeNull());
  });

  it('cuts no text and holds no banned word', async () => {
    const { container } = mount();
    await screen.findByTestId('rule-acknowledge');
    expect(container.querySelector('.truncate, [class*="line-clamp"], .text-ellipsis')).toBeNull();
    expect(forbiddenWords(container)).toEqual([]);
  });
});

// Round 3, part 2 (F3): the button states how many alerts the press closes.
describe('RuleDecisionBar: the plan of each choice', () => {
  const plans = [
    { includeWeak: false, investigations: 470, alerts: 486, inherit: 844, held: 12, capped: false },
    { includeWeak: true, investigations: 471, alerts: 487, inherit: 844, held: 11, capped: false },
  ];

  it('states the alerts of the investigations, the alerts that inherit and the alerts that stay open', async () => {
    vi.mocked(getRuleDecision).mockResolvedValue(ruleDetail({ plans, planKnown: true, scanMax: 2000 }));
    mount();
    expect(await screen.findByTestId('rule-acknowledge-writes')).toHaveTextContent(
      'Writes: soc-ai acknowledges 486 alerts of these investigations and 844 alerts that inherit their verdict ' +
        'in Security Onion. 12 alerts of this rule stay open: a verdict of their own holds them.',
    );
    fireEvent.click(screen.getByTestId('rule-include-weak'));
    expect(screen.getByTestId('rule-acknowledge-writes')).toHaveTextContent('acknowledges 487 alerts of these investigations');
    expect(screen.getByTestId('rule-acknowledge-writes')).toHaveTextContent('11 alerts of this rule stay open');
  });

  it('states that the scan of the grid stopped at its limit', async () => {
    vi.mocked(getRuleDecision).mockResolvedValue(
      ruleDetail({ plans: plans.map((p) => ({ ...p, capped: true })), planKnown: true, scanMax: 2000 }),
    );
    mount();
    expect(await screen.findByTestId('rule-acknowledge-writes')).toHaveTextContent(
      'The scan of the grid stopped at 2,000 alerts. More alerts can inherit the verdict.',
    );
  });

  // NEGATIVE CONTROL: a grid that did not answer gives no count.
  it('states that the count of the alerts is unknown when the grid did not answer', async () => {
    vi.mocked(getRuleDecision).mockResolvedValue(ruleDetail({ plans: [], planKnown: false }));
    mount();
    expect(await screen.findByTestId('rule-acknowledge-writes')).toHaveTextContent(
      'The grid did not answer, so the count of the alerts is unknown.',
    );
  });

  it('offers the group with weak evidence on the main button when no false positive has checked evidence', async () => {
    vi.mocked(getRuleDecision).mockResolvedValue(
      ruleDetail({
        confident: { count: 0, reasons: [], sources: 0, destinations: 0, firstEvent: null, lastEvent: null },
        weak: {
          count: 28,
          reasons: [{ code: 'below_threshold', label: 'The confidence is below the threshold.', count: 28 }],
          sources: 1,
          destinations: 1,
          firstEvent: '2026-11-10T00:00:00Z',
          lastEvent: '2026-11-14T00:00:00Z',
        },
        plans: [{ includeWeak: true, investigations: 28, alerts: 28, inherit: 3, held: 0, capped: false }],
        planKnown: true,
      }),
    );
    mount();
    const main = await screen.findByTestId('rule-acknowledge');
    expect(main).toHaveTextContent('Acknowledge the 28 false positives with weak evidence');
    expect(main).not.toHaveTextContent('Acknowledge the 0');
    expect(screen.getByTestId('rule-weak-first')).toHaveTextContent('Read the samples first.');
    expect(screen.queryByTestId('rule-include-weak')).toBeNull();
    expect(screen.getByTestId('rule-acknowledge-writes')).toHaveTextContent('acknowledges 28 alerts of these investigations');
    fireEvent.click(main);
    await waitFor(() =>
      expect(postRuleDecision).toHaveBeenCalledWith(RULE_KEY, { decision: 'acknowledge', includeWeak: true, note: '' }),
    );
  });

  it('states the window of the count of the open alerts', async () => {
    vi.mocked(getRuleDecision).mockResolvedValue(ruleDetail({ openAlerts: 0, openAlertsDays: 30 }));
    mount();
    expect(await screen.findByTestId('rule-open-alerts')).toHaveTextContent(
      'The grid holds 0 open alerts of this rule in the last 30 days.',
    );
  });
});

// Round 3, part 2 (F4): the false positives on the machines of a true positive.
describe('RuleDecisionBar: the machines of a true positive', () => {
  const tpDetail = () =>
    ruleDetail({
      truePositives: [{ id: 'inv-tp', eventAt: '2026-11-12T08:00:00Z', title: 'ET POLICY Example TLS client' }],
      truePositivePairs: { confident: 20, weak: 0 },
      plans: [
        { includeWeak: false, includeTruePositivePairs: false, investigations: 450, alerts: 450, inherit: 9, held: 3, capped: false },
        { includeWeak: false, includeTruePositivePairs: true, investigations: 470, alerts: 470, inherit: 30, held: 2, capped: false },
        { includeWeak: true, includeTruePositivePairs: false, investigations: 451, alerts: 451, inherit: 9, held: 2, capped: false },
        { includeWeak: true, includeTruePositivePairs: true, investigations: 471, alerts: 471, inherit: 30, held: 1, capped: false },
      ],
      planKnown: true,
      canStanding: false,
      canStandingWhy: 'This rule holds a true positive verdict that stands.',
    });

  it('leaves the false positives on the machines of the true positive out of the main button', async () => {
    vi.mocked(getRuleDecision).mockResolvedValue(tpDetail());
    mount();
    const main = await screen.findByTestId('rule-acknowledge');
    expect(main).toHaveTextContent('Acknowledge the 450 false positives with checked evidence');
    expect(screen.getByTestId('rule-acknowledge-writes')).toHaveTextContent('acknowledges 450 alerts of these investigations');
    const box = screen.getByTestId('rule-include-true-positive-pairs') as HTMLInputElement;
    // NEGATIVE CONTROL: the third choice is off by default.
    expect(box.checked).toBe(false);
    expect(box.closest('label')).toHaveTextContent('Also the 20 on the machines of the true positive');
    fireEvent.click(main);
    await waitFor(() =>
      expect(postRuleDecision).toHaveBeenCalledWith(RULE_KEY, { decision: 'acknowledge', includeWeak: false, note: '' }),
    );
  });

  it('adds them when the analyst selects the third choice', async () => {
    vi.mocked(getRuleDecision).mockResolvedValue(tpDetail());
    mount();
    fireEvent.click(await screen.findByTestId('rule-include-true-positive-pairs'));
    expect(screen.getByTestId('rule-acknowledge')).toHaveTextContent('Acknowledge the 470 false positives with checked evidence');
    expect(screen.getByTestId('rule-acknowledge-writes')).toHaveTextContent('acknowledges 470 alerts of these investigations');
    fireEvent.click(screen.getByTestId('rule-acknowledge'));
    await waitFor(() =>
      expect(postRuleDecision).toHaveBeenCalledWith(RULE_KEY, {
        decision: 'acknowledge',
        includeWeak: false,
        note: '',
        includeTruePositivePairs: true,
      }),
    );
  });

  // NEGATIVE CONTROL: no false positive on the machines of a true positive, no third choice.
  it('offers no third choice for a rule with no false positive on the machines of a true positive', async () => {
    mount();
    await screen.findByTestId('rule-acknowledge');
    expect(screen.queryByTestId('rule-include-true-positive-pairs')).toBeNull();
  });
});
