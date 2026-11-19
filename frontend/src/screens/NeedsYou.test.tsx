import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { NeedsYou } from './NeedsYou';

vi.mock('../lib/api', async () => {
  const actual = await vi.importActual<typeof import('../lib/api')>('../lib/api');
  return { ...actual, getNeedsYouItems: vi.fn(), getNeedsYouCount: vi.fn() };
});
import { ApiError, getNeedsYouCount, getNeedsYouItems, type NeedsYouCount, type NeedsYouItems } from '../lib/api';
import { forbiddenWords } from '../test/analystWords';

const NOW = new Date('2026-11-14T12:00:00Z');

const ITEMS: NeedsYouItems = {
  total: 14,
  items: [
    {
      type: 'campaign',
      id: '7',
      title: 'actor-a against web-1',
      detail: 'The campaign reached Action on the target and waits on your decision.',
      since: '2026-10-01T00:00:00Z',
      href: '/campaigns/7',
      stage: 'action',
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
      type: 'investigation',
      id: 'run-nmi',
      title: 'ET POLICY SSH session',
      detail: 'The verdict needs more info.',
      since: '2026-11-12T09:00:00Z',
      href: '/investigation/run-nmi',
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
      type: 'alerts',
      id: 'alerts',
      title: 'Alert groups with no verdict',
      detail: '9 alert groups have no verdict in the last 7 days.',
      since: '2026-11-08T03:00:00Z',
      href: '/alerts?range=7d&verdict=untriaged',
      stage: null,
    },
  ],
};

const PREPARED = {
  type: 'investigation' as const,
  id: 'run-tp',
  title: 'ET EXPLOIT Example Upload Request',
  detail: '1 recommended action waits.',
  since: '2026-11-14T10:00:00Z',
  href: '/investigation/run-tp',
  stage: null,
  verdict: 'true_positive',
  confidence: 0.85,
  impact: 'succeeded' as const,
  severity: 'high' as const,
  machines: [
    { name: 'ws-1', address: '192.0.2.10' },
    { name: null, address: '198.51.100.7' },
  ],
  machinesMore: 2,
  eventAt: '2026-11-14T09:00:00Z',
  why: '1 recommended action waits for a person.',
  action: { label: 'Escalate to case', writes: 'Opens a case in Security Onion.' },
};

const COUNT: NeedsYouCount = {
  leads_needing_decision: 1,
  campaigns: 2,
  unread_shadow_hits: 0,
  untriaged_groups: 9,
  needs_more_info: 1,
  pending_actions: 0,
  investigations_waiting: 1,
  decisions: 13,
  review: 0,
  total: 13,
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
  vi.mocked(getNeedsYouItems).mockReset().mockResolvedValue(ITEMS);
  vi.mocked(getNeedsYouCount).mockReset().mockResolvedValue(COUNT);
});

describe('NeedsYou', () => {
  it('keeps the order of the server, the most important first, and states the order', async () => {
    mount();
    const rows = await screen.findAllByTestId('needs-you-item');
    // The server orders the list (needs_you_facts.order_key). The page sorted
    // each type by its oldest item, and the live lead was the last row.
    expect(rows.map((r) => within(r).getByTestId('needs-you-item-title').textContent)).toEqual(
      ITEMS.items.map((i) => i.title),
    );
    expect(screen.getByTestId('needs-you-scope')).toHaveTextContent(
      'the most important first: campaigns, true positives, leads, other investigations, rules with open false positives, then alert groups.',
    );
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
    // One phrase for the wait on the whole page. Past 30 days the age takes the
    // warning color.
    expect(within(old).getByTestId('needs-you-item-age')).toHaveTextContent('Waits for 44 days');
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

  // NY3. The row is prepared for the decision: the marks lead, then the
  // title, the machines, the action in words and the wait.
  it('leads each row with the verdict and the impact, and names the machines and the action', async () => {
    vi.mocked(getNeedsYouItems).mockResolvedValue({ items: [PREPARED], total: 1 });
    mount();
    const row = await screen.findByTestId('needs-you-item');
    const marks = within(row).getByTestId('needs-you-item-marks');
    expect(marks).toHaveTextContent('True positive');
    expect(within(marks).getByTestId('impact-chip')).toHaveAttribute('data-impact', 'succeeded');
    expect(within(marks).getByTestId('severity-tag')).toHaveTextContent('High');
    // The marks come before the title.
    const title = within(row).getByTestId('needs-you-item-title');
    expect(marks.compareDocumentPosition(title) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    const chips = within(row).getAllByTestId('needs-you-machine');
    expect(chips.map((c) => c.textContent)).toEqual(['ws-1192.0.2.10', '198.51.100.7']);
    expect(chips[1]).toHaveAttribute('title', 'soc-ai holds no name for this machine. Address: 198.51.100.7.');
    expect(within(row).getByTestId('needs-you-machines-more')).toHaveTextContent('2 more machines');
    expect(within(row).getByTestId('needs-you-item-action')).toHaveTextContent(
      'Escalate to case. Opens a case in Security Onion.',
    );
    expect(within(row).getByTestId('needs-you-item-detail')).toHaveTextContent('1 recommended action waits for a person.');
    expect(within(row).getByTestId('needs-you-item-age')).toHaveTextContent('Waits for 2 hours');
    // No row writes: the row holds one link and no button.
    expect(within(row).getAllByRole('link')).toHaveLength(1);
    expect(within(row).queryByRole('button')).toBeNull();
  });

  it('states the earlier decision and the new facts of a campaign that opened again (SD3)', async () => {
    const reopened = {
      type: 'campaign' as const,
      id: '2',
      title: 'actor-a against web-1',
      detail: 'Stage reached: Action on the target. 1,118 alert events.',
      since: '2026-11-14T08:02:00Z',
      href: '/campaigns/2',
      stage: 'action' as const,
      verdict: 'true_positive',
      machines: [
        { name: 'actor-a', address: '192.0.2.10' },
        { name: null, address: '198.51.100.20' },
      ],
      machinesMore: 3,
      why: 'Opened again on 2026-11-14 08:02 UTC by new activity. casey closed it on 2026-11-12: Test that is over.',
      newFacts:
        'New: 5 true positive investigations and 1 false positive from actor-a, 2026-11-14 07:55 to 08:12 UTC. An authorization holds 3.',
      action: { label: 'Decide on the campaign', writes: 'soc-ai stores the decision.' },
    };
    vi.mocked(getNeedsYouItems).mockResolvedValue({ items: [reopened, ITEMS.items[1]], total: 2 });
    mount();
    const [row, other] = await screen.findAllByTestId('needs-you-item');
    expect(within(row).getByTestId('needs-you-item-detail')).toHaveTextContent(reopened.why);
    expect(within(row).getByTestId('needs-you-item-new')).toHaveTextContent(reopened.newFacts);
    // The machine that acted again comes first, in sight.
    expect(within(row).getAllByTestId('needs-you-machine')[0]).toHaveTextContent('actor-a');
    expect(forbiddenWords(row)).toEqual([]);
    // NEGATIVE CONTROL: a campaign that never had a decision states no new facts.
    expect(within(other).queryByTestId('needs-you-item-new')).toBeNull();
  });

  it('opens the item when the analyst selects the row', async () => {
    vi.mocked(getNeedsYouItems).mockResolvedValue({ items: [PREPARED], total: 1 });
    render(
      <MemoryRouter initialEntries={['/needs-you']}>
        <Routes>
          <Route path="/needs-you" element={<NeedsYou />} />
          <Route path="/investigation/:id" element={<p>investigation page</p>} />
        </Routes>
      </MemoryRouter>,
    );
    fireEvent.click(await screen.findByTestId('needs-you-item-title'));
    expect(await screen.findByText('investigation page')).toBeInTheDocument();
  });

  // NEGATIVE CONTROL. A value that soc-ai does not hold shows as unknown.
  it('shows an unknown value as unknown', async () => {
    const lead = {
      ...ITEMS.items.find((i) => i.type === 'lead')!,
      verdict: null,
      confidence: null,
      impact: null,
      severity: null,
      machines: null,
      machinesMore: 0,
      why: 'No hunt read the lead, and the lead has no decision.',
      action: { label: 'Hunt the lead', writes: 'soc-ai starts a hunt. Nothing goes to Security Onion.' },
    };
    const tp = { ...PREPARED, impact: null, severity: null };
    vi.mocked(getNeedsYouItems).mockResolvedValue({ items: [tp, lead], total: 2 });
    mount();
    const [tpRow, leadRow] = await screen.findAllByTestId('needs-you-item');
    // A true positive that states no impact reads "Impact unknown".
    expect(within(tpRow).getByTestId('impact-chip')).toHaveTextContent('Impact unknown');
    expect(within(tpRow).getByTestId('severity-tag')).toHaveTextContent('Unknown');
    // A lead holds no verdict and no impact. Its severity is unknown.
    expect(within(leadRow).getByTestId('needs-you-item-marks')).toHaveTextContent('No verdict');
    expect(within(leadRow).queryByTestId('impact-chip')).toBeNull();
    expect(within(leadRow).getByTestId('severity-tag')).toHaveTextContent('Unknown');
    expect(within(leadRow).getByTestId('needs-you-item-machines')).toHaveTextContent('No machine is on record.');
    // The observation types of a lead stay on the row under `why`.
    expect(within(leadRow).getByTestId('needs-you-item-extra')).toHaveTextContent('The lead waits on a decision.');
  });

  // OW5. A heading for each group with its count, the event time that the
  // order reads, a direction only when the record holds a source and a target.
  it('states a heading with its count for each group, in the order of the server', async () => {
    const tp2 = { ...PREPARED, id: 'run-tp-2', title: 'ET EXPLOIT Second Request' };
    const nmi = ITEMS.items.find((i) => i.id === 'run-nmi')!;
    const campaigns = ITEMS.items.filter((i) => i.type === 'campaign');
    const rest = ITEMS.items.filter((i) => i.type === 'lead' || i.type === 'alerts');
    vi.mocked(getNeedsYouItems).mockResolvedValue({
      items: [...campaigns, PREPARED, tp2, rest[0], nmi, rest[1]],
      total: 16,
    });
    mount();
    await screen.findAllByTestId('needs-you-item');
    expect(screen.getAllByTestId('needs-you-group-heading').map((h) => h.textContent)).toEqual([
      'Campaigns · 2',
      'True positive investigations · 2',
      'Leads · 1',
      'Other investigations · 1',
      // The one item of the alert groups counts its groups.
      'Alert groups with no verdict · 9',
    ]);
  });

  it('shows the time of the event that the order reads', async () => {
    vi.mocked(getNeedsYouItems).mockResolvedValue({ items: [PREPARED, { ...PREPARED, id: 'x', eventAt: null }], total: 2 });
    mount();
    const [row, unknown] = await screen.findAllByTestId('needs-you-item');
    expect(within(row).getByTestId('needs-you-item-event')).toHaveTextContent('Event 2026-11-14 09:00 UTC');
    expect(within(unknown).getByTestId('needs-you-item-event')).toHaveTextContent('Event time unknown');
  });

  it('shows a direction only when the record holds a source and a target', async () => {
    const pair = { ...PREPARED, machinesMore: 0, machinesDirected: true };
    const hosts = { ...PREPARED, id: 'run-hosts', machinesMore: 0, machinesDirected: false };
    vi.mocked(getNeedsYouItems).mockResolvedValue({ items: [pair, hosts], total: 2 });
    mount();
    const [directed, plain] = await screen.findAllByTestId('needs-you-item');
    expect(within(directed).getByTestId('needs-you-machines-arrow')).toBeTruthy();
    expect(within(directed).getAllByTestId('needs-you-machine')[0]).toHaveAttribute(
      'title',
      'Source. Name: ws-1. Address: 192.0.2.10.',
    );
    // NEGATIVE CONTROL: no pair on record, no arrow.
    expect(within(plain).queryByTestId('needs-you-machines-arrow')).toBeNull();
  });

  it('reads one impact chip for a true positive and none for a verdict that needs more info', async () => {
    const tp = { ...PREPARED, impact: null };
    const nmi = { ...PREPARED, id: 'run-nmi-2', verdict: 'needs_more_info', impact: 'attempted' as const };
    vi.mocked(getNeedsYouItems).mockResolvedValue({ items: [tp, nmi], total: 2 });
    mount();
    const [tpRow, nmiRow] = await screen.findAllByTestId('needs-you-item');
    expect(within(tpRow).getAllByTestId('impact-chip')).toHaveLength(1);
    expect(within(tpRow).getByTestId('impact-chip')).toHaveTextContent('Impact unknown');
    expect(within(nmiRow).queryByTestId('impact-chip')).toBeNull();
  });

  // NY4. A line of the Dashboard tile or of the bell opens the page with a
  // type filter. The chips state the parts of the one count.
  it('shows the items of the type filter and lights its chip', async () => {
    mount('/needs-you?type=campaign');
    const rows = await screen.findAllByTestId('needs-you-item');
    expect(rows.map((r) => r.getAttribute('data-type'))).toEqual(['campaign', 'campaign']);
    const chip = screen.getByTestId('needs-you-filter-campaign');
    expect(chip).toHaveAttribute('aria-current', 'page');
    expect(await within(chip).findByText('2')).toBeInTheDocument();
    expect(screen.getByTestId('needs-you-filter-alerts')).toHaveTextContent('Alert groups9');
    expect(screen.getByTestId('needs-you-filter-lead')).toHaveAttribute('href', '/needs-you?type=lead');
    // The heading keeps the number of the top bar.
    expect(screen.getByTestId('needs-you-total')).toHaveTextContent('14 decisions wait on you.');
  });

  it('states an empty type in words', async () => {
    vi.mocked(getNeedsYouItems).mockResolvedValue({ items: ITEMS.items.filter((i) => i.type !== 'lead'), total: 13 });
    mount('/needs-you?type=lead');
    expect(await screen.findByText('No lead waits on you.')).toBeInTheDocument();
    expect(screen.queryByTestId('needs-you-item')).toBeNull();
  });

  // NEGATIVE CONTROL. A filter value that is no type hides nothing.
  it('shows every item for a filter value that is no type', async () => {
    mount('/needs-you?type=shadow');
    expect(await screen.findAllByTestId('needs-you-item')).toHaveLength(ITEMS.items.length);
    expect(screen.getByRole('link', { name: 'Every type' })).toHaveAttribute('aria-current', 'page');
  });
});
