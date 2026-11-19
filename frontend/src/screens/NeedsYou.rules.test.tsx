// The rules with open false positives on the Needs you page (round 3, RC1).
// soc-ai gives a false positive verdict and a guard holds the automatic
// acknowledge. The row of the rule states the facts of one decision for the
// whole rule: the verdict, the count of each group, the severity, the
// machines, the span of the events, why it waits and what the action writes.
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { NeedsYou } from './NeedsYou';

vi.mock('../lib/api', async () => {
  const actual = await vi.importActual<typeof import('../lib/api')>('../lib/api');
  return { ...actual, getNeedsYouItems: vi.fn(), getNeedsYouCount: vi.fn() };
});
import { getNeedsYouCount, getNeedsYouItems, type NeedsYouCount, type NeedsYouItem } from '../lib/api';
import { forbiddenWords } from '../test/analystWords';

const NOW = new Date('2026-11-14T12:00:00Z');

const RULE: NeedsYouItem = {
  type: 'rule',
  id: 'RVQgUE9MSUNZIEV4YW1wbGUgVExTIGNsaWVudA',
  title: 'ET POLICY Example TLS client',
  detail: 'soc-ai holds the acknowledge of 471 false positives of this rule.',
  verdict: 'false_positive',
  confidence: 0.82,
  impact: null,
  severity: 'high',
  machines: [
    { name: 'ws-1', address: '192.0.2.10' },
    { name: 'web-1', address: '198.51.100.7' },
  ],
  machinesMore: 3,
  eventAt: '2026-11-14T09:00:00Z',
  since: '2026-10-01T00:00:00Z',
  count: 471,
  confident: 470,
  weak: 1,
  why: 'soc-ai holds the acknowledge of 471 false positives of this rule. The rule is high stakes.',
  action: {
    label: 'Decide on the rule',
    writes: 'The rule page states what each decision writes before the press.',
  },
  href: '/needs-you/rule/RVQgUE9MSUNZIEV4YW1wbGUgVExTIGNsaWVudA',
};

const OTHER: NeedsYouItem = {
  type: 'investigation',
  id: 'inv-nmi',
  title: 'ET POLICY SSH session',
  detail: 'The verdict needs more info.',
  since: '2026-11-12T09:00:00Z',
  href: '/investigation/inv-nmi',
  verdict: 'needs_more_info',
};

const ALERTS: NeedsYouItem = {
  type: 'alerts',
  id: 'alerts',
  title: 'Alert groups with no verdict',
  detail: '9 alert groups have no verdict in the last 7 days.',
  since: '2026-11-08T03:00:00Z',
  href: '/alerts?range=7d&verdict=untriaged',
};

const COUNT: NeedsYouCount = {
  leads_needing_decision: 0,
  campaigns: 0,
  unread_shadow_hits: 0,
  untriaged_groups: 9,
  needs_more_info: 1,
  pending_actions: 0,
  investigations_waiting: 1,
  rules_waiting: 1,
  decisions: 11,
  review: 0,
  total: 11,
  unknown: [],
  alert_window: '7d',
  verdict_window: 'all',
  alert_floor: false,
};

function mount(path = '/needs-you') {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <NeedsYou />
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(NOW);
  vi.mocked(getNeedsYouItems).mockReset().mockResolvedValue({ items: [OTHER, RULE, ALERTS], total: 11 });
  vi.mocked(getNeedsYouCount).mockReset().mockResolvedValue(COUNT);
});

describe('Needs you: the rules with open false positives', () => {
  it('puts the rules in their own group after the other investigations and before the alert groups', async () => {
    mount();
    const headings = await screen.findAllByTestId('needs-you-group-heading');
    expect(headings.map((h) => h.textContent)).toEqual([
      'Other investigations · 1',
      'Rules with open false positives · 1',
      'Alert groups with no verdict · 9',
    ]);
    expect(screen.getByTestId('needs-you-scope')).toHaveTextContent(
      'other investigations, rules with open false positives, then alert groups.',
    );
  });

  it('prepares the row of a rule with the facts of the decision', async () => {
    mount();
    const row = (await screen.findAllByTestId('needs-you-item')).find((r) => r.dataset.type === 'rule')!;
    expect(within(row).getByTestId('needs-you-item-type')).toHaveTextContent('Rule');
    expect(within(row).getByTestId('needs-you-item-title')).toHaveTextContent('ET POLICY Example TLS client');
    // The marks lead: the verdict with the median confidence, and the severity.
    const marks = within(row).getByTestId('needs-you-item-marks');
    expect(marks).toHaveTextContent('False positive');
    expect(marks).toHaveTextContent('0.82');
    expect(marks).toHaveTextContent(/high/i);
    // The count of each group, as one graphic and in words.
    expect(within(row).getByTestId('needs-you-rule-count')).toHaveTextContent(
      '471 investigations: 470 with checked evidence, 1 with weak evidence',
    );
    expect(within(row).getByTestId('needs-you-rule-split')).toHaveAttribute(
      'aria-label',
      '471 investigations: 470 with checked evidence, 1 with weak evidence',
    );
    expect(within(row).getByTestId('needs-you-rule-span')).toHaveTextContent(
      'Events from 2026-10-01 00:00 UTC to 2026-11-14 09:00 UTC',
    );
    expect(within(row).getAllByTestId('needs-you-machine')).toHaveLength(2);
    expect(within(row).getByTestId('needs-you-machines-more')).toHaveTextContent('3 more machines');
    expect(within(row).getByTestId('needs-you-item-detail')).toHaveTextContent('The rule is high stakes.');
    expect(within(row).getByTestId('needs-you-item-action')).toHaveTextContent(
      'Decide on the rule. The rule page states what each decision writes before the press.',
    );
    expect(within(row).getByTestId('needs-you-item-age')).toHaveTextContent('Waits for 44 days');
    const link = within(row).getByRole('link', { name: /Open the rule/ });
    expect(link).toHaveAttribute('href', RULE.href);
  });

  // NEGATIVE CONTROL: the row states the count of the server. A console sum
  // of the two groups would read 4 here.
  it('states the count of the server, also when the groups do not add up to it', async () => {
    vi.mocked(getNeedsYouItems).mockResolvedValue({
      items: [{ ...RULE, count: 5, confident: 3, weak: 1 }],
      total: 1,
    });
    mount();
    const count = await screen.findByTestId('needs-you-rule-count');
    expect(count).toHaveTextContent('5 investigations: 3 with checked evidence, 1 with weak evidence');
  });

  it('names no weak group for a rule with no weak evidence', async () => {
    vi.mocked(getNeedsYouItems).mockResolvedValue({
      items: [{ ...RULE, count: 12, confident: 12, weak: 0 }],
      total: 1,
    });
    mount();
    const count = await screen.findByTestId('needs-you-rule-count');
    expect(count.textContent).toBe('12 investigations: 12 with checked evidence');
    expect(screen.getByTestId('needs-you-rule-split').querySelectorAll('rect')).toHaveLength(1);
  });

  it('offers the type filter Rules with the count of the rules, and the filter shows the rules only', async () => {
    mount('/needs-you?type=rule');
    const chip = await screen.findByTestId('needs-you-filter-rule');
    expect(chip).toHaveTextContent('Rules');
    expect(chip).toHaveAttribute('href', '/needs-you?type=rule');
    expect(chip).toHaveAttribute('aria-current', 'page');
    expect(await screen.findByText('1', { selector: '[data-testid="needs-you-filter-rule"] span' })).toBeTruthy();
    const rows = screen.getAllByTestId('needs-you-item');
    expect(rows.map((r) => r.dataset.type)).toEqual(['rule']);
  });

  it('states that no rule waits under the filter Rules', async () => {
    vi.mocked(getNeedsYouItems).mockResolvedValue({ items: [OTHER], total: 1 });
    mount('/needs-you?type=rule');
    expect(await screen.findByText('No rule with open false positives waits on you.')).toBeInTheDocument();
  });

  it('cuts no text and holds no banned word', async () => {
    const { container } = mount();
    await screen.findByTestId('needs-you-rule-count');
    expect(container.querySelector('.truncate, [class*="line-clamp"], .text-ellipsis')).toBeNull();
    expect(forbiddenWords(container)).toEqual([]);
    expect(container.textContent).not.toMatch(/\bkinds?\b/i);
  });
});
