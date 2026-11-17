import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { NeedsYou } from './NeedsYou';

vi.mock('../lib/api', async () => {
  const actual = await vi.importActual<typeof import('../lib/api')>('../lib/api');
  return { ...actual, getNeedsYouItems: vi.fn() };
});
import { ApiError, getNeedsYouItems, type NeedsYouItems } from '../lib/api';
import { forbiddenWords } from '../test/analystWords';

const NOW = new Date('2026-11-14T12:00:00Z');

const ITEMS: NeedsYouItems = {
  total: 14,
  items: [
    {
      type: 'alerts',
      id: 'alerts',
      title: 'Alert groups with no verdict',
      detail: '9 alert groups have no verdict in the last 7 days.',
      since: '2026-11-08T03:00:00Z',
      href: '/alerts?range=7d&verdict=untriaged',
      stage: null,
    },
    {
      type: 'lead',
      id: '18',
      title: 'Beacon from mail-1 to 203.0.113.9',
      detail: 'The lead waits on a decision.',
      since: '2026-11-10T09:00:00Z',
      href: '/leads/18',
      stage: null,
    },
    {
      type: 'investigation',
      id: 'run-nmi',
      title: 'ET POLICY SSH session',
      detail: 'The verdict needs more info.',
      since: '2026-11-12T09:00:00Z',
      href: '/investigation/run-nmi',
      stage: null,
    },
    {
      type: 'campaign',
      id: '9',
      title: 'scanner-2 against db-1',
      detail: 'The campaign waits on your decision.',
      since: '2026-11-11T00:00:00Z',
      href: '/campaigns/9',
      stage: 'attempt',
    },
    {
      type: 'campaign',
      id: '7',
      title: 'actor-a against web-1',
      detail: 'The campaign reached Action on the target and waits on your decision.',
      since: '2026-10-01T00:00:00Z',
      href: '/campaigns/7',
      stage: 'action',
    },
  ],
};

function mount() {
  return render(
    <MemoryRouter>
      <NeedsYou />
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.useFakeTimers({ toFake: ['Date'] });
  vi.setSystemTime(NOW);
  vi.mocked(getNeedsYouItems).mockReset().mockResolvedValue(ITEMS);
});

describe('NeedsYou', () => {
  it('lists the campaigns first, then each type with its oldest item first', async () => {
    mount();
    const rows = await screen.findAllByTestId('needs-you-item');
    expect(rows.map((r) => r.getAttribute('data-type'))).toEqual([
      'campaign',
      'campaign',
      'investigation',
      'lead',
      'alerts',
    ]);
    expect(rows.map((r) => within(r).getByTestId('needs-you-item-title').textContent)).toEqual([
      'actor-a against web-1',
      'scanner-2 against db-1',
      'ET POLICY SSH session',
      'Beacon from mail-1 to 203.0.113.9',
      'Alert groups with no verdict',
    ]);
  });

  it('states the total of the top bar with its scope', async () => {
    mount();
    expect(await screen.findByTestId('needs-you-total')).toHaveTextContent('14 decisions wait on you.');
    expect(screen.getByTestId('needs-you-scope')).toHaveTextContent('at any age');
  });

  it('gives each row its type, a graphic, why it waits, its age and one link', async () => {
    mount();
    const [old, recent, inv] = await screen.findAllByTestId('needs-you-item');
    expect(within(old).getByTestId('needs-you-item-type')).toHaveTextContent('Campaign');
    expect(within(old).getByTestId('stage-meter')).toHaveAttribute('data-stage', 'action');
    expect(within(old).getByTestId('needs-you-item-detail')).toHaveTextContent(
      'The campaign reached Action on the target and waits on your decision.',
    );
    // Past 30 days the age states the days with no decision.
    expect(within(old).getByTestId('needs-you-item-age')).toHaveTextContent('No decision for 44 days');
    expect(within(old).getByTestId('needs-you-item-age')).toHaveAttribute('data-old', 'true');
    expect(within(recent).getByTestId('needs-you-item-age')).toHaveTextContent('Waits for 3 days');
    const links = within(old).getAllByRole('link');
    expect(links).toHaveLength(1);
    expect(links[0]).toHaveAttribute('href', '/campaigns/7');
    expect(links[0]).toHaveTextContent('Open the campaign');
    expect(within(inv).queryByTestId('stage-meter')).toBeNull();
    expect(within(inv).getByRole('link')).toHaveTextContent('Open the investigation');
  });

  it('cuts no text and holds no banned word', async () => {
    const { container } = mount();
    await screen.findAllByTestId('needs-you-item');
    expect(container.querySelector('.truncate, [class*="line-clamp"], .text-ellipsis')).toBeNull();
    expect(forbiddenWords(container)).toEqual([]);
    expect(container.textContent).not.toMatch(/\bkinds?\b/i);
  });

  it('shows the long detail of an investigation beyond the authorization whole', async () => {
    // The server writes the alarm as the first sentence of `detail`.
    const detail =
      'Beyond the authorization of the campaign actor-a and 203.0.113.50 against web-1, db-1 and the file server of the branch office. ' +
      '2 actions wait on your decision: block the source address at the firewall and acknowledge the alerts in Security Onion.';
    vi.mocked(getNeedsYouItems).mockResolvedValue({
      items: [{ ...ITEMS.items.find((i) => i.type === 'investigation')!, id: 'run-beyond', detail }],
      total: 1,
    });
    const { container } = mount();
    const row = await screen.findByTestId('needs-you-item');
    const shown = within(row).getByTestId('needs-you-item-detail');
    expect(shown.textContent).toBe(detail);
    expect(shown.className).toContain('break-words');
    // NEGATIVE CONTROL: nothing on the row cuts the text.
    expect(container.querySelector('.truncate, [class*="line-clamp"], .text-ellipsis, .whitespace-nowrap [data-testid="needs-you-item-detail"]')).toBeNull();
  });

  it('states that nothing needs the analyst', async () => {
    vi.mocked(getNeedsYouItems).mockResolvedValue({ items: [], total: 0 });
    mount();
    expect(await screen.findByText('Nothing needs you.')).toBeInTheDocument();
    expect(screen.queryByTestId('needs-you-unread')).toBeNull();
  });

  // The top bar marks a part that soc-ai could not read with "+". The heading
  // states the same floor and names the types it could not read.
  it('states a floor and names each type that soc-ai could not read', async () => {
    vi.mocked(getNeedsYouItems).mockResolvedValue({ ...ITEMS, unknown: ['campaign', 'alerts'] });
    mount();
    expect(await screen.findByTestId('needs-you-total')).toHaveTextContent('At least 14 decisions wait on you.');
    expect(screen.getByTestId('needs-you-unread')).toHaveTextContent(
      'soc-ai could not read the campaigns and the alert groups.',
    );
  });

  // NEGATIVE CONTROL. A floor of zero is no "Nothing needs you" heading.
  it('states no zero count when soc-ai could not read a type', async () => {
    vi.mocked(getNeedsYouItems).mockResolvedValue({ items: [], total: 0, unknown: ['investigation'] });
    mount();
    expect(await screen.findByTestId('needs-you-total')).toHaveTextContent('soc-ai could not count what needs you.');
    expect(screen.getByTestId('needs-you-unread')).toHaveTextContent('soc-ai could not read the investigations.');
    expect(screen.queryByText('Nothing needs you.')).toBeNull();
    expect(screen.getByText('The list holds no item that soc-ai could read.')).toBeInTheDocument();
  });

  it('states a failed read with a Retry, never an empty list', async () => {
    vi.mocked(getNeedsYouItems).mockRejectedValue(new ApiError('Service unavailable', 503));
    mount();
    expect(await screen.findByRole('button', { name: /retry/i })).toBeInTheDocument();
    expect(screen.queryByText('Nothing needs you.')).toBeNull();
  });
});
