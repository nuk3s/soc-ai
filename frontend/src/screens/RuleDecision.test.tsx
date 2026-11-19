// The page "Rule decision" (round 3, RC2). Graphical first: one bar chart of
// the events for each UTC day with the two groups stacked, then the machines,
// then the two groups with their hold reasons and their samples.
import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { RuleDecision } from './RuleDecision';

vi.mock('../lib/api', async () => {
  const actual = await vi.importActual<typeof import('../lib/api')>('../lib/api');
  return { ...actual, getRuleDecision: vi.fn() };
});
import { ApiError, getRuleDecision } from '../lib/api';
import { forbiddenWords } from '../test/analystWords';
import { RULE_KEY, ruleDetail } from '../test/ruleDecision';

function mount(key = RULE_KEY) {
  return render(
    <MemoryRouter initialEntries={[`/needs-you/rule/${key}`]}>
      <Routes>
        <Route path="/needs-you/rule/:ruleKey" element={<RuleDecision />} />
      </Routes>
    </MemoryRouter>,
  );
}

const before = (a: Element, b: Element) =>
  (a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING) !== 0;

beforeEach(() => {
  vi.mocked(getRuleDecision).mockReset().mockResolvedValue(ruleDetail());
});

describe('RuleDecision', () => {
  it('reads the rule of the key and states the count of each group', async () => {
    mount();
    expect(await screen.findByTestId('rule-name')).toHaveTextContent('ET POLICY Example TLS client');
    expect(getRuleDecision).toHaveBeenCalledWith(RULE_KEY);
    expect(screen.getByTestId('rule-summary')).toHaveTextContent(
      '471 open false positives of this rule: 470 with checked evidence, 1 with weak evidence.',
    );
    expect(screen.getByTestId('rule-open-alerts')).toHaveTextContent('The grid holds 1,204 open alerts of this rule.');
  });

  it('leads with the chart, then the machines, then the two groups', async () => {
    mount();
    const chart = await screen.findByTestId('rule-day-bars');
    const machines = screen.getByTestId('rule-machines');
    const confident = screen.getByTestId('rule-group-confident');
    const weak = screen.getByTestId('rule-group-weak');
    expect(before(chart, machines)).toBe(true);
    expect(before(machines, confident)).toBe(true);
    expect(before(confident, weak)).toBe(true);
  });

  it('draws one bar for each UTC day with the two groups stacked, and a gap day with no bar', async () => {
    mount();
    const days = await screen.findAllByTestId('rule-day');
    expect(days.map((d) => d.getAttribute('data-day'))).toEqual([
      '2026-11-10',
      '2026-11-11',
      '2026-11-12',
      '2026-11-13',
      '2026-11-14',
    ]);
    const gap = days[1];
    expect(gap.querySelector('[data-testid="rule-day-confident"]')).toBeNull();
    expect(gap.querySelector('[data-testid="rule-day-weak"]')).toBeNull();
    const mixed = days[3];
    const base = mixed.querySelector('[data-testid="rule-day-confident"]')!;
    const top = mixed.querySelector('[data-testid="rule-day-weak"]')!;
    // The weak part sits on top of the confident part.
    expect(Number(top.getAttribute('y')) + Number(top.getAttribute('height'))).toBeCloseTo(Number(base.getAttribute('y')));
    expect(within(mixed).getByRole('img')).toHaveAttribute(
      'aria-label',
      '2026-11-13 UTC: 151 investigations, 150 with checked evidence, 1 with weak evidence.',
    );
    // The keyboard reaches each bar, and the tooltip states its day.
    fireEvent.focus(within(mixed).getByRole('img'));
    expect(await screen.findByTestId('rule-day-tip')).toHaveTextContent('2026-11-13 UTC: 151 investigations');
    expect(screen.getByTestId('rule-day-legend')).toHaveTextContent('Checked evidence 470');
    expect(screen.getByTestId('rule-day-legend')).toHaveTextContent('Weak evidence 1');
  });

  it('lists the machines with their role and their count', async () => {
    mount();
    const rows = await screen.findAllByTestId('rule-machine');
    expect(rows).toHaveLength(2);
    expect(rows[0]).toHaveAttribute('data-role', 'source');
    expect(rows[0]).toHaveTextContent('Source');
    expect(rows[0]).toHaveTextContent('ws-1');
    expect(rows[0]).toHaveTextContent('192.0.2.10');
    expect(within(rows[1]).getByTestId('rule-machine-count')).toHaveTextContent('471 investigations');
    expect(within(rows[1]).getByRole('link', { name: 'web-1' })).toHaveAttribute('href', '/hosts/198.51.100.7');
  });

  it('states the hold reasons of each group with counts and shows its samples', async () => {
    mount();
    const confident = await screen.findByTestId('rule-group-confident');
    expect(within(confident).getByTestId('rule-group-confident-count')).toHaveTextContent('470');
    const reasons = within(confident).getAllByTestId('rule-reason');
    expect(reasons.map((r) => r.textContent)).toEqual([
      'The rule is high stakes468 investigations',
      'The automatic acknowledge failed2 investigations',
    ]);
    expect(confident).toHaveTextContent('4 source machines and 2 destination machines.');
    const samples = within(confident).getAllByTestId('rule-sample');
    expect(samples).toHaveLength(2);
    const first = samples[0];
    expect(within(first).getByTestId('rule-sample-time')).toHaveTextContent('2026-11-14 09:00 UTC');
    expect(within(first).getByTestId('rule-sample-machines')).toHaveTextContent('192.0.2.10');
    expect(within(first).getByTestId('rule-sample-machines')).toHaveTextContent('198.51.100.7');
    expect(first).toHaveTextContent('0.86');
    expect(within(first).getByTestId('rule-sample-summary')).toHaveTextContent(
      'The client fetched a known update file from the vendor host.',
    );
    expect(within(first).getByTestId('rule-sample-reason')).toHaveTextContent('Held: The rule is high stakes.');
    expect(within(first).getByRole('link', { name: /Open the investigation/ })).toHaveAttribute(
      'href',
      '/investigation/inv-a',
    );
    const weak = screen.getByTestId('rule-group-weak');
    expect(within(weak).getAllByTestId('rule-sample')).toHaveLength(1);
    expect(within(weak).getByTestId('rule-reason')).toHaveTextContent('The confidence is under the limit');
  });

  it('states a group with no open false positive', async () => {
    vi.mocked(getRuleDecision).mockResolvedValue(
      ruleDetail({ weak: { count: 0, reasons: [], sources: 0, destinations: 0, firstEvent: null, lastEvent: null } }),
    );
    mount();
    const weak = await screen.findByTestId('rule-group-weak');
    expect(weak).toHaveTextContent('No open false positive of this rule has weak evidence.');
  });

  it('states a true positive of the rule at the top in the danger color with the link', async () => {
    vi.mocked(getRuleDecision).mockResolvedValue(
      ruleDetail({ truePositives: [{ id: 'inv-tp', eventAt: '2026-11-09T22:00:00Z', title: 'ET POLICY Example TLS client' }] }),
    );
    mount();
    const alarm = await screen.findByTestId('rule-true-positives');
    expect(alarm).toHaveTextContent('This rule also holds 1 true positive verdict. Read it before a decision.');
    expect(alarm.className).toContain('border-danger');
    expect(within(alarm).getByRole('link', { name: /Open the investigation/ })).toHaveAttribute(
      'href',
      '/investigation/inv-tp',
    );
    expect(before(alarm, screen.getByTestId('rule-day-bars'))).toBe(true);
  });

  // NEGATIVE CONTROL: no true positive, no alarm.
  it('shows no alarm for a rule with no true positive', async () => {
    mount();
    await screen.findByTestId('rule-day-bars');
    expect(screen.queryByTestId('rule-true-positives')).toBeNull();
  });

  it('states the read time of the grid when the grid did not answer', async () => {
    vi.mocked(getRuleDecision).mockResolvedValue(ruleDetail({ gridAnswered: false, openAlerts: null }));
    mount();
    expect(await screen.findByTestId('rule-grid-read')).toHaveTextContent(
      'The grid did not answer. The counts are from the read of 2026-11-14 11:58 UTC.',
    );
    expect(screen.queryByTestId('rule-open-alerts')).toBeNull();
  });

  it('states that soc-ai did not read the grid yet', async () => {
    vi.mocked(getRuleDecision).mockResolvedValue(ruleDetail({ readAt: null }));
    mount();
    expect(await screen.findByTestId('rule-grid-read')).toHaveTextContent(
      'soc-ai did not read the grid for these alerts yet. Each alert counts as open.',
    );
  });

  // NEGATIVE CONTROL: a good read states no read time.
  it('states no read time when the grid answered', async () => {
    mount();
    await screen.findByTestId('rule-day-bars');
    expect(screen.queryByTestId('rule-grid-read')).toBeNull();
  });

  it('answers a key that no rule holds as not found', async () => {
    vi.mocked(getRuleDecision).mockRejectedValue(new ApiError('Not found', 404, 'rule_not_found'));
    mount('bm8tc3VjaC1ydWxl');
    expect(await screen.findByText('No such rule')).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Back to Needs you/ })).toHaveAttribute('href', '/needs-you');
  });

  it('states that soc-ai acknowledges the rule by itself, and offers no standing choice', async () => {
    const sentence =
      'soc-ai acknowledges the false positives of this rule by itself since 2026-11-13 UTC. ' +
      'The 468 here are from before that date.';
    vi.mocked(getRuleDecision).mockResolvedValue(
      ruleDetail({
        selfAcknowledging: { since: '2026-11-13T23:40:38Z', acknowledged: 58, before: 468, sentence },
        canStanding: false,
        canStandingWhy:
          'soc-ai acknowledges the false positives of this rule by itself since 2026-11-13 UTC. ' +
          'A standing decision adds nothing.',
      }),
    );
    mount();
    expect(await screen.findByTestId('rule-self-ack')).toHaveTextContent(sentence);
    expect(screen.queryByTestId('rule-standing-choice')).toBeNull();
    expect(screen.getByTestId('rule-standing-refused')).toHaveTextContent('A standing decision adds nothing.');
  });

  // NEGATIVE CONTROL: a rule that the guard still holds states no such fact.
  it('states no acknowledge by itself for a rule that the guard holds', async () => {
    mount();
    await screen.findByTestId('rule-day-bars');
    expect(screen.queryByTestId('rule-self-ack')).toBeNull();
  });

  it('marks the day and the machines of a true positive, and states the false positives on its machines', async () => {
    vi.mocked(getRuleDecision).mockResolvedValue(
      ruleDetail({
        truePositives: [{ id: 'inv-tp', eventAt: '2026-11-08T22:00:00Z', title: 'ET POLICY Example TLS client' }],
        truePositivePairs: { confident: 12, weak: 1 },
        machines: [
          { key: '192.0.2.10', name: 'ws-1', address: '192.0.2.10', role: 'source', count: 300, truePositive: true },
          { key: '198.51.100.7', name: 'web-1', address: '198.51.100.7', role: 'destination', count: 471 },
        ],
      }),
    );
    mount();
    expect(await screen.findByTestId('rule-true-positive-pairs')).toHaveTextContent(
      '13 of the open false positives are on the machines of a true positive. The main button leaves them out.',
    );
    const rows = screen.getAllByTestId('rule-machine');
    expect(within(rows[0]).getByTestId('rule-machine-true-positive')).toHaveTextContent('True positive');
    expect(within(rows[1]).queryByTestId('rule-machine-true-positive')).toBeNull();
    // The axis reaches the day of the true positive, before the first false positive.
    const marked = screen.getAllByTestId('rule-day').filter((d) => d.querySelector('[data-testid="rule-day-true-positive"]'));
    expect(marked.map((d) => d.getAttribute('data-day'))).toEqual(['2026-11-08']);
    expect(within(marked[0]).getByRole('img').getAttribute('aria-label')).toContain(
      'A true positive of this rule is on this day.',
    );
    expect(screen.getByTestId('rule-day-legend-true-positive')).toHaveTextContent('True positive');
  });

  it('ends the hold reason of a sample with one period', async () => {
    const detail = ruleDetail();
    detail.confident.reasons = detail.confident.reasons.map((r) =>
      r.code === 'high_stakes' ? { ...r, label: 'The alert is high or critical, or a malware or exploit alert.' } : r,
    );
    vi.mocked(getRuleDecision).mockResolvedValue(detail);
    mount();
    const reasons = await screen.findAllByTestId('rule-sample-reason');
    expect(reasons[0].textContent).toBe('Held: The alert is high or critical, or a malware or exploit alert.');
    for (const r of reasons) expect(r.textContent).not.toMatch(/\.\.$/);
  });

  it('gives the last day its label, and the label before it gives way', async () => {
    const days = Array.from({ length: 30 }, (_, i) => ({
      day: new Date(Date.UTC(2026, 9, 15 + i)).toISOString().slice(0, 10),
      confident: 1,
      weak: 0,
    }));
    vi.mocked(getRuleDecision).mockResolvedValue(ruleDetail({ histogram: days }));
    mount();
    await screen.findByTestId('rule-day-bars');
    const shown = screen
      .getAllByTestId('rule-day')
      .map((g, i) => ({ i, label: g.querySelector('[data-testid="rule-day-label"]') }))
      .filter((d) => d.label !== null)
      .map((d) => d.i);
    expect(shown.length).toBeLessThan(30);
    expect(shown[shown.length - 1]).toBe(29);
    const gaps = shown.slice(1).map((i, k) => i - shown[k]);
    // Each gap is at least the regular step: no label sits on its neighbour.
    expect(Math.min(...gaps)).toBeGreaterThanOrEqual(gaps[0]);
  });

  it('cuts no text and holds no banned word', async () => {
    const { container } = mount();
    await screen.findByTestId('rule-day-bars');
    expect(container.querySelector('.truncate, [class*="line-clamp"], .text-ellipsis')).toBeNull();
    expect(forbiddenWords(container)).toEqual([]);
    expect(container.textContent).not.toMatch(/\bkinds?\b/i);
  });
});
