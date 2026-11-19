import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { Campaigns } from './Campaigns';

vi.mock('../lib/api', async () => {
  const actual = await vi.importActual<typeof import('../lib/api')>('../lib/api');
  return { ...actual, getCampaigns: vi.fn() };
});
import { ApiError, getCampaigns, type CampaignList, type CampaignRow } from '../lib/api';
import { UNKNOWN, UNKNOWN_TONE } from '../components/Kpi';
import { forbiddenWords } from '../test/analystWords';

const ROW: CampaignRow = {
  id: 7,
  title: 'actor-a against web-1',
  status: 'open',
  stage: 'action',
  actors: [
    { machineKey: 'agent:actor-a', name: 'actor-a', address: '192.0.2.10' },
    { machineKey: 'net:198.51.100.7', name: null, address: '198.51.100.7' },
  ],
  targets: [
    { machineKey: 'agent:web-1', name: 'web-1', address: '192.0.2.20' },
    { machineKey: 'agent:web-2', name: 'web-2', address: '192.0.2.21' },
    { machineKey: 'agent:web-3', name: 'web-3', address: '192.0.2.22' },
  ],
  targetsMore: 4,
  firstEvent: '2026-10-24T01:11:00Z',
  lastEvent: '2026-10-28T22:44:56Z',
  members: 63,
  alerts: 1072,
};

const LIST: CampaignList = { rows: [ROW], total: 1, stale: false };

function mount(at = '/campaigns') {
  return render(
    <MemoryRouter initialEntries={[at]}>
      <Routes>
        <Route path="/campaigns" element={<Campaigns />} />
      </Routes>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  vi.mocked(getCampaigns).mockReset().mockResolvedValue(LIST);
});

describe('Campaigns', () => {
  it('shows one row for each campaign', async () => {
    mount();
    const row = await screen.findByTestId('campaign-row-7');
    expect(screen.getByRole('heading', { name: 'Campaigns' })).toBeInTheDocument();
    expect(within(row).getByRole('link', { name: 'actor-a against web-1' })).toHaveAttribute(
      'href',
      '/campaigns/7',
    );
    expect(within(row).getByTestId('campaign-state')).toHaveTextContent('Open');
    expect(within(row).getByTestId('campaign-stage')).toHaveTextContent('Action on the target');
    // A party name links to its host page. A party with no name reads its address.
    expect(within(row).getByRole('link', { name: 'actor-a' })).toHaveAttribute(
      'href',
      '/hosts/agent%3Aactor-a',
    );
    expect(within(row).getByRole('link', { name: '198.51.100.7' })).toBeInTheDocument();
    expect(within(row).getByTestId('campaign-targets')).toHaveTextContent('web-1, web-2, web-3 and 4 more');
    expect(row).toHaveTextContent('2026-10-24 01:11 to 2026-10-28 22:44 UTC');
    // The last column counts the alert events. The count of investigations is no column.
    const head = within(screen.getByTestId('campaigns-table')).getAllByRole('columnheader');
    expect(head.map((h) => h.textContent)).toEqual(['Campaign', 'State', 'Stage', 'Actors', 'Targets', 'Period', 'Alerts']);
    expect(within(row).getByTestId('campaign-row-alerts')).toHaveTextContent('1,072');
    expect(row).not.toHaveTextContent('63');
    // NEGATIVE CONTROL: a current count states no read time.
    expect(within(row).queryByTestId('campaign-row-alerts-read')).toBeNull();
  });

  it('states the grid read of a count that can be behind its campaign (SD5)', async () => {
    vi.mocked(getCampaigns).mockResolvedValue({
      ...LIST,
      rows: [{ ...ROW, alertsBehind: true, alertsReadAt: '2026-11-18T12:40:00Z' }],
    });
    mount();
    const row = await screen.findByTestId('campaign-row-7');
    expect(within(row).getByTestId('campaign-row-alerts-read')).toHaveTextContent('Grid read 2026-11-18 12:40 UTC');
  });

  it('marks the alerts unknown when the campaign holds no stored events or the server sends none', async () => {
    const { alerts: _alerts, ...earlier } = ROW;
    vi.mocked(getCampaigns).mockResolvedValue({
      ...LIST,
      rows: [{ ...ROW, alerts: null }, { ...earlier, id: 8 }],
      total: 2,
    });
    mount();
    for (const id of [7, 8]) {
      const cell = within(await screen.findByTestId(`campaign-row-${id}`)).getByTestId('campaign-row-alerts');
      expect(cell.textContent).toBe(UNKNOWN);
      expect(cell.querySelector('span')?.className).toBe(UNKNOWN_TONE);
    }
  });

  it('says no "run" and no "member" on the list', async () => {
    mount();
    await screen.findByTestId('campaign-row-7');
    const texts = [document.body.textContent ?? ''];
    for (const el of document.body.querySelectorAll('[aria-label], [title]')) {
      texts.push(el.getAttribute('aria-label') ?? '', el.getAttribute('title') ?? '');
    }
    expect(texts.join('\n').match(/\b(run|runs|member|members)\b/gi)).toBeNull();
  });

  it('renders no stage chip for a campaign with no stage, and no "more" for three targets', async () => {
    vi.mocked(getCampaigns).mockResolvedValue({
      ...LIST,
      rows: [{ ...ROW, stage: null, targetsMore: 0 }],
    });
    mount();
    const row = await screen.findByTestId('campaign-row-7');
    expect(within(row).queryByTestId('campaign-stage')).toBeNull();
    expect(within(row).getByTestId('campaign-targets').textContent).toBe('web-1, web-2, web-3');
  });

  it('states how a campaign forms when there is none', async () => {
    vi.mocked(getCampaigns).mockResolvedValue({ rows: [], total: 0, stale: false });
    mount();
    const empty = await screen.findByTestId('campaigns-empty');
    expect(empty).toHaveTextContent(
      'No campaign. A campaign forms from a true positive alert or finding with a known source machine and target machine.',
    );
    expect(empty.textContent?.match(/\b(run|runs|member|members)\b/gi)).toBeNull();
    expect(screen.queryByTestId('campaigns-table')).toBeNull();
  });

  it('shows the error card with a Retry that reads again', async () => {
    vi.mocked(getCampaigns).mockRejectedValueOnce(new ApiError('boom', 500));
    mount();
    expect(await screen.findByText('Could not load the campaigns')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Retry' }));
    expect(await screen.findByTestId('campaign-row-7')).toBeInTheDocument();
    expect(getCampaigns).toHaveBeenCalledTimes(2);
  });

  it('states a stale list over the rows of the last build', async () => {
    vi.mocked(getCampaigns).mockResolvedValue({ ...LIST, stale: true });
    mount();
    await screen.findByTestId('campaign-row-7');
    expect(screen.getByRole('status')).toHaveTextContent('soc-ai retries automatically.');
  });

  // NEGATIVE CONTROL: a fresh list states no notice.
  it('states no notice over a fresh list', async () => {
    mount();
    await screen.findByTestId('campaign-row-7');
    expect(screen.queryByRole('status')).toBeNull();
  });
});

// Pages are graphical first (owner, 2026-11-14). Each row draws the stage
// meter in its Stage cell, beside the stage in words.
describe('Campaigns stage meter', () => {
  it('draws the stage meter in each row, before the stage chip', async () => {
    vi.mocked(getCampaigns).mockResolvedValue({
      ...LIST,
      rows: [ROW, { ...ROW, id: 8, title: 'actor-b against db-1', stage: null }],
    });
    mount();
    const row = await screen.findByTestId('campaign-row-7');
    const cell = within(row).getByTestId('campaign-row-stage');
    const meter = within(cell).getByRole('img');
    expect(meter).toHaveAccessibleName('Stage reached: Action on the target, 4 of 5');
    const chip = within(cell).getByTestId('campaign-stage');
    expect(meter.compareDocumentPosition(chip) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    // NEGATIVE CONTROL. A campaign with no proven stage fills no segment.
    const other = within(screen.getByTestId('campaign-row-8')).getByTestId('campaign-row-stage');
    expect(within(other).getByRole('img')).toHaveAccessibleName('No proven stage');
    expect(other.querySelector('[data-filled="true"]')).toBeNull();
    expect(forbiddenWords(screen.getByTestId('campaigns-table'))).toEqual([]);
  });

  it('states the decision of each campaign and filters the campaigns that wait on the analyst', async () => {
    vi.mocked(getCampaigns).mockResolvedValue({
      rows: [
        { ...ROW, id: 7, decision: null, waitsSince: '2026-10-24T01:11:00Z' },
        { ...ROW, id: 8, title: 'actor-b against db-1', decision: 'closed', waitsSince: null },
        { ...ROW, id: 9, title: 'actor-c against mail-1', decision: null, waitsSince: '2026-11-01T00:00:00Z' },
      ],
      total: 3,
      stale: false,
    });
    mount();
    const waits = await screen.findByTestId('campaign-row-7');
    expect(within(waits).getByTestId('campaign-state').textContent).toBe('Open');
    expect(within(waits).getByTestId('campaign-state')).toHaveAttribute('data-waits', 'true');
    // One chip on a decided row: the decision, never "Open" beside it.
    const closed = screen.getByTestId('campaign-row-8');
    expect(within(closed).getAllByTestId('campaign-state').map((c) => c.textContent)).toEqual(['Closed']);
    const filter = screen.getByTestId('campaigns-filter');
    const all = within(filter).getByRole('button', { name: 'All 3' });
    const waitsOnYou = within(filter).getByRole('button', { name: 'Waits on you 2' });
    expect(all).toHaveAttribute('aria-pressed', 'true');
    fireEvent.click(waitsOnYou);
    expect(waitsOnYou).toHaveAttribute('aria-pressed', 'true');
    expect(screen.getAllByTestId(/^campaign-row-\d+$/).map((r) => r.getAttribute('data-testid'))).toEqual([
      'campaign-row-7',
      'campaign-row-9',
    ]);
    fireEvent.click(all);
    expect(screen.getAllByTestId(/^campaign-row-\d+$/)).toHaveLength(3);
  });

  it('states a campaign with a case as Case, and no campaign with a case waits', async () => {
    vi.mocked(getCampaigns).mockResolvedValue({
      rows: [
        { ...ROW, id: 7, decision: 'case', waitsSince: null },
        { ...ROW, id: 9, title: 'actor-c against mail-1', decision: null, waitsSince: '2026-11-01T00:00:00Z' },
      ],
      total: 2,
      stale: false,
    });
    mount();
    const row = await screen.findByTestId('campaign-row-7');
    const chip = within(row).getByTestId('campaign-state');
    expect(chip.textContent).toBe('Case');
    expect(chip).toHaveAttribute('data-state', 'case');
    expect(chip).toHaveAttribute('title', 'A Security Onion case holds this campaign.');
    // NEGATIVE CONTROL: a case is a decision, so the filter counts it out.
    expect(within(screen.getByTestId('campaigns-filter')).getByRole('button', { name: 'Waits on you 1' })).toBeInTheDocument();
    expect(forbiddenWords(row)).toEqual([]);
  });

  it('states the expiry of an authorization and the alarm of the investigations beyond it', async () => {
    const expiresAt = new Date(Date.now() + 7 * 86_400_000).toISOString();
    vi.mocked(getCampaigns).mockResolvedValue({
      rows: [
        { ...ROW, id: 7, decision: 'authorized', waitsSince: null, authorization: { expiresAt, state: 'active' }, beyond: 3 },
        { ...ROW, id: 8, title: 'actor-b against db-1', decision: 'authorized', waitsSince: null, beyond: 0 },
      ],
      total: 2,
      stale: false,
    });
    mount();
    const row = await screen.findByTestId('campaign-row-7');
    expect(within(row).getByTestId('campaign-state').textContent).toBe('Authorized');
    expect(within(row).getByTestId('campaign-state').getAttribute('title')).toMatch(/^An authorization covers this campaign until /);
    const alarm = within(row).getByTestId('campaign-beyond-chip');
    expect(alarm.textContent).toBe('3 beyond the authorization');
    expect(alarm.className).toContain('text-danger');
    expect(alarm.getAttribute('title')).toBe(
      '3 investigations are beyond the authorization. Each one keeps normal handling and waits on you.',
    );
    // NEGATIVE CONTROL: a count of 0 and no authorization field state the plain chip and no alarm.
    const other = screen.getByTestId('campaign-row-8');
    expect(within(other).getByTestId('campaign-state').textContent).toBe('Authorized');
    expect(within(other).queryByTestId('campaign-beyond-chip')).toBeNull();
    expect(forbiddenWords(row)).toEqual([]);
  });

  it('opens on the filter that the Campaigns badge links to', async () => {
    vi.mocked(getCampaigns).mockResolvedValue({
      rows: [
        { ...ROW, id: 7, decision: null, waitsSince: '2026-10-24T01:11:00Z' },
        { ...ROW, id: 8, decision: 'closed', waitsSince: null },
      ],
      total: 2,
      stale: false,
    });
    mount('/campaigns?decision=waits');
    await screen.findByTestId('campaign-row-7');
    expect(screen.queryByTestId('campaign-row-8')).toBeNull();
    expect(within(screen.getByTestId('campaigns-filter')).getByRole('button', { name: 'Waits on you 1' })).toHaveAttribute(
      'aria-pressed',
      'true',
    );
  });

  it('opens on the filter of the decided campaigns that the Confirmed threats panel links to', async () => {
    vi.mocked(getCampaigns).mockResolvedValue({
      rows: [
        { ...ROW, id: 7, decision: null, waitsSince: '2026-10-24T01:11:00Z', state: 'open' },
        { ...ROW, id: 8, title: 'actor-b against db-1', decision: 'closed', waitsSince: null, state: 'closed' },
        { ...ROW, id: 9, title: 'actor-c against mail-1', decision: 'case', waitsSince: null, state: 'case' },
      ],
      total: 3,
      stale: false,
    });
    mount('/campaigns?decision=decided');
    await screen.findByTestId('campaign-row-8');
    // NEGATIVE CONTROL: a campaign with no decision is no decided campaign.
    expect(screen.queryByTestId('campaign-row-7')).toBeNull();
    expect(screen.getByTestId('campaign-row-9')).toBeInTheDocument();
    const filter = screen.getByTestId('campaigns-filter');
    expect(within(filter).getByRole('button', { name: 'Decided 2' })).toHaveAttribute('aria-pressed', 'true');
    expect(within(filter).getByRole('button', { name: 'Waits on you 1' })).toHaveAttribute('aria-pressed', 'false');
    // N15: the Decided line of the panel counts a window. The list states
    // that it holds every decided campaign.
    expect(screen.getByTestId('campaigns-decided-all').textContent).toBe(
      'The list shows every decided campaign, from any time.',
    );
    fireEvent.click(within(filter).getByRole('button', { name: 'All 3' }));
    expect(screen.getAllByTestId(/^campaign-row-\d+$/)).toHaveLength(3);
    // Negative control: the full list states no such line.
    expect(screen.queryByTestId('campaigns-decided-all')).toBeNull();
  });

  it('states that no campaign holds a decision when the decided filter holds none', async () => {
    vi.mocked(getCampaigns).mockResolvedValue({ rows: [{ ...ROW, decision: null, waitsSince: '2026-10-24T01:11:00Z' }], total: 1, stale: false });
    mount('/campaigns?decision=decided');
    expect(await screen.findByText('No campaign holds a decision.')).toBeInTheDocument();
  });

  it('states that no campaign waits when the filter holds none', async () => {
    vi.mocked(getCampaigns).mockResolvedValue({ rows: [{ ...ROW, decision: 'closed', waitsSince: null }], total: 1, stale: false });
    mount('/campaigns?decision=waits');
    expect(await screen.findByText('No campaign waits on your decision.')).toBeInTheDocument();
  });

  it('shows no filter and claims no wait for a server that sends no decision', async () => {
    mount('/campaigns?decision=waits');
    // NEGATIVE CONTROL. With no decision field the filter would hide every row.
    expect(await screen.findByTestId('campaign-row-7')).toBeInTheDocument();
    expect(screen.queryByTestId('campaigns-filter')).toBeNull();
    expect(screen.getByTestId('campaign-state')).toHaveAttribute('data-waits', 'false');
  });
});
