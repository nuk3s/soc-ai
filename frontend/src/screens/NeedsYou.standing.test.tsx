// The fold "Standing rule decisions" of Needs you (round 3, RC5). It lists
// each standing decision in force with its end date and its count. It is
// closed by default and absent when none exists.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { NeedsYou } from './NeedsYou';

vi.mock('../lib/api', async () => {
  const actual = await vi.importActual<typeof import('../lib/api')>('../lib/api');
  return { ...actual, getNeedsYouItems: vi.fn(), getNeedsYouCount: vi.fn(), getRuleDecisions: vi.fn() };
});
import { getNeedsYouCount, getNeedsYouItems, getRuleDecisions, ruleKeyOf, type RuleDecisionList } from '../lib/api';
import { forbiddenWords } from '../test/analystWords';

const STANDING = 'ET INFO Example update check';

const LIST: RuleDecisionList = {
  standing: [
    {
      id: 4,
      ruleKey: ruleKeyOf(STANDING),
      ruleName: STANDING,
      decision: 'standing',
      by: 'ana',
      at: '2026-11-10T08:00:00Z',
      endsAt: '2026-12-10T08:00:00Z',
      acknowledged: 37,
    },
  ],
  ended: [
    {
      id: 2,
      ruleKey: ruleKeyOf('ET INFO Example old rule'),
      ruleName: 'ET INFO Example old rule',
      decision: 'standing',
      by: 'ana',
      at: '2026-09-01T08:00:00Z',
      endedAt: '2026-10-01T08:00:00Z',
      endCause: 'expired',
    },
  ],
};

function mount() {
  return render(
    <MemoryRouter initialEntries={['/needs-you']}>
      <NeedsYou />
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.mocked(getNeedsYouItems).mockReset().mockResolvedValue({ items: [], total: 0 });
  vi.mocked(getNeedsYouCount).mockReset().mockRejectedValue(new Error('not read'));
  vi.mocked(getRuleDecisions).mockReset().mockResolvedValue(LIST);
});

describe('Needs you: the standing rule decisions', () => {
  it('is one fold, closed by default, with the count of the decisions in force', async () => {
    mount();
    const fold = await screen.findByTestId('needs-you-standing');
    expect(fold).toHaveAttribute('data-open', 'false');
    expect(fold).toHaveTextContent('Standing rule decisions');
    expect(within(fold).getByTestId('needs-you-standing-count')).toHaveTextContent('1');
    expect(within(fold).queryByTestId('needs-you-standing-row')).toBeNull();
  });

  it('lists each decision in force with its end date, its count and the link of its rule', async () => {
    mount();
    fireEvent.click(await screen.findByRole('button', { name: 'Expand Standing rule decisions' }));
    const rows = await screen.findAllByTestId('needs-you-standing-row');
    // The decision that ended is no row.
    expect(rows).toHaveLength(1);
    expect(rows[0]).toHaveTextContent(STANDING);
    expect(within(rows[0]).getByTestId('needs-you-standing-facts')).toHaveTextContent(
      'In force until 2026-12-10 08:00 UTC. soc-ai acknowledged 37 later false positives under it. ana made it at 2026-11-10 08:00 UTC.',
    );
    expect(within(rows[0]).getByRole('link', { name: /Open the rule/ })).toHaveAttribute(
      'href',
      `/needs-you/rule/${ruleKeyOf(STANDING)}`,
    );
  });

  // NEGATIVE CONTROL: no standing decision in force, no fold.
  it('is absent when no standing decision is in force', async () => {
    vi.mocked(getRuleDecisions).mockResolvedValue({ standing: [], ended: LIST.ended });
    mount();
    await screen.findByText('Nothing needs you.');
    await waitFor(() => expect(getRuleDecisions).toHaveBeenCalled());
    expect(screen.queryByTestId('needs-you-standing')).toBeNull();
  });

  // NEGATIVE CONTROL: a failed read shows no fold and keeps the list.
  it('is absent when the read fails', async () => {
    vi.mocked(getRuleDecisions).mockRejectedValue(new Error('503'));
    mount();
    await screen.findByText('Nothing needs you.');
    await waitFor(() => expect(getRuleDecisions).toHaveBeenCalled());
    expect(screen.queryByTestId('needs-you-standing')).toBeNull();
  });

  it('cuts no text and holds no banned word', async () => {
    const { container } = mount();
    fireEvent.click(await screen.findByRole('button', { name: 'Expand Standing rule decisions' }));
    await screen.findAllByTestId('needs-you-standing-row');
    expect(container.querySelector('.truncate, [class*="line-clamp"], .text-ellipsis')).toBeNull();
    expect(forbiddenWords(container)).toEqual([]);
  });
});
