// One tile, three denominators (dogfood 2026-09-07, D4). "True positives · 24h"
// is labelled for a 24-hour window, its number counts DETECTION GROUPS, and its
// subtext counted INVESTIGATION RUNS over thirty days. Read in two tabs at the
// same minute the tile said one and the investigations list said three, and
// nothing on the tile said the two were counting different things.
//
// Every number in the tile now names the unit and the window it answers for.
//
// Review 2026-11-12 (ui-core 3): the tile said 3 and the outcomes card said 0
// for one window, and no element named the hosts. The tile now states the
// total of the Confirmed threats panel, from the same answer, and the panel
// is the first block of the page.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { ThreatList } from '../lib/api';
import type { AlertGroup, InvestigationList, InvestigationRow, Verdict } from '../lib/types';

const group = (id: string, verdict: Verdict): AlertGroup => ({
  id,
  name: `ET TEST ${id}`,
  kind: 'suricata',
  sev: 'high',
  count: 4,
  verdict,
  conf: verdict === 'untriaged' ? null : 0.8,
  latest: '2m ago',
  inherited: false,
  events: [],
});

// One true positive among three groups: the shape the range was in when the
// tile read "1" beside a 24h investigations list reading "3 true positives".
const GROUPS: [string, Verdict][] = [
  ['g-tp', 'true_positive'],
  ['g-fp', 'false_positive'],
  ['g-nmi', 'needs_more_info'],
];

const listInvestigations = vi.hoisted(() => vi.fn());
const getThreats = vi.hoisted(() => vi.fn());

const empty = (): InvestigationList => ({
  rows: [] as InvestigationRow[],
  total: 0,
  running: 0,
  truePositives: 0,
  totalAll: 0,
  active: false,
  limit: 100,
  offset: 0,
});

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAlerts: vi.fn().mockResolvedValue({ groups: [], truncated: false, other_docs: 0 }),
  getDossierConflicts: vi.fn().mockResolvedValue({ pending: 0, rows: [] }),
  getQualityEvalStatus: vi.fn().mockResolvedValue({ running: false }),
  listInvestigations,
  getThreats,
  getAutoTriageStatus: vi.fn().mockResolvedValue({ active: false, hunted: 0, total: 0 }),
  getDataSources: vi.fn().mockResolvedValue({ sources: [] }),
  getQualityTrend: vi.fn().mockResolvedValue({ points: [] }),
  getHealth: vi.fn().mockResolvedValue(null),
  getDetectionTuningSummary: vi.fn().mockResolvedValue(null),
  getMe: vi.fn().mockResolvedValue({ username: 'ana', role: 'analyst', status: '' }),
  getPreflight: vi.fn().mockResolvedValue({ status: 'green', failing: 0, warned: 0, checked_at: '2026-08-19T00:00:00+00:00' }),
  getPreflightDetail: vi.fn().mockResolvedValue({ rows: [], checked_at: '2026-08-19T00:00:00+00:00' }),
}));

import { queueOf } from '../test/alertQueue';
import { Dashboard } from './Dashboard';
import { getAlerts } from '../lib/api';

const fallback = (id: string): InvestigationRow => ({
  id,
  name: `Run ${id}`,
  kind: 'suricata',
  verdict: 'needs_more_info',
  conf: 0.3,
  host: '192.0.2.10',
  status: 'complete',
  when: '2d ago',
  ts: '2026-08-20T10:00:00+00:00',
  alertId: `ev-${id}`,
  isPrimary: true,
  fallback: true,
});

const threatsOf = (total: number): ThreatList => ({
  window: { since: new Date(Date.now() - 86_400_000).toISOString(), until: new Date().toISOString() },
  rows: [
    {
      target: { address: '10.20.30.5', name: 'mainsrv', role: 'web server', machineKey: 'agent:m1' },
      direction: 'inbound',
      headline: 'An exploit chain ran against the web server.',
      impact: 'succeeded',
      runs: total - 2,
      alertRuns: total - 2,
      findingRuns: 0,
      sources: [{ address: '10.40.50.7', name: null }],
      sourcesMore: 0,
      rules: [],
      rulesMore: 0,
      firstSeen: new Date(Date.now() - 3_600_000).toISOString(),
      lastSeen: new Date(Date.now() - 600_000).toISOString(),
      waitingActions: 0,
      newestInvestigationId: 'inv-1',
      investigationsHref: '/investigations?entity=agent%3Am1',
    },
  ],
  authorized: [
    {
      authorization: { id: 3, label: 'Red team test', state: 'active', expiresAt: new Date(Date.now() + 86_400_000).toISOString() },
      target: { address: '10.20.30.20', name: 'lab01', role: null, machineKey: 'agent:lab' },
      direction: 'inbound',
      runs: 2,
      lastSeen: new Date(Date.now() - 600_000).toISOString(),
      runsHref: '/investigations?authorization=3&range=all',
    },
  ],
  total,
});

const mount = async (pipelineErrors: InvestigationRow[] = []) => {
  vi.mocked(getAlerts).mockResolvedValue(queueOf(GROUPS.map(([id, v]) => group(id, v))));
  // NEGATIVE CONTROL source: the Investigations list states 99 true
  // positives. The tile must not read it.
  listInvestigations.mockImplementation(async (q: { verdict?: string[] } = {}) =>
    q.verdict?.length
      ? { ...empty(), rows: pipelineErrors, total: pipelineErrors.length }
      : { ...empty(), total: 120, truePositives: 99 },
  );
  getThreats.mockReset().mockResolvedValue(threatsOf(15));
  render(
    <MemoryRouter>
      <Dashboard />
    </MemoryRouter>,
  );
  await screen.findByText('Investigation outcomes');
};

/** The whole true-positives tile (the Panel), located from its label. */
const tpTile = async () =>
  (await screen.findByText('True positives that wait · 24h')).closest('.rounded-panel')!;

describe('Dashboard true-positives tile — every number answers one question', () => {
  it('states the total of the Confirmed threats answer, over the window', async () => {
    await mount();
    const tile = await tpTile();
    await waitFor(() => expect(screen.getByTestId('tp-total').textContent).toBe('15'));
    // The panel states the same number from the same answer.
    expect(screen.getByTestId('confirmed-threats-total').textContent).toBe('15 true positives');
    // Two hosts: one threat row and one authorized group.
    expect(within(tile as HTMLElement).getByTestId('tp-hosts').textContent).toBe('on 2 hosts in this window');
    // One read serves the tile and the panel.
    expect(getThreats).toHaveBeenCalledTimes(1);
    // The 24h window.
    const since = Date.parse(getThreats.mock.calls[0][0].since);
    expect(Math.abs(Date.now() - since - 24 * 3_600_000)).toBeLessThan(60_000);
    // NEGATIVE CONTROL: the count of the Investigations list does not reach the tile.
    expect(tile.textContent).not.toContain('99');
  });

  it('puts the Confirmed threats panel above the tiles', async () => {
    await mount();
    const tile = await tpTile();
    const panel = screen.getByTestId('confirmed-threats');
    expect(panel.compareDocumentPosition(tile) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    // A fixed block: it is not a cell of the panel grid, so no saved layout moves it.
    expect(panel.closest('.dash-cell')).toBeNull();
    expect(await screen.findAllByTestId('threat-row')).toHaveLength(1);
  });

  it('links to the true positives list, with the window and the verdict filter', async () => {
    await mount();
    const tile = await tpTile();
    await waitFor(() => expect(tile.textContent).toContain('Open them'));
    const link = screen.getByRole('link', { name: 'Open them' });
    expect(link.getAttribute('href')).toBe('/investigations?range=24h&verdict=true_positive&waits=true');
  });

  it('reads the new window when the range changes', async () => {
    await mount();
    await tpTile();
    fireEvent.click(screen.getByText('7d'));
    expect(await screen.findByText('True positives that wait · 7d')).toBeTruthy();
    expect(await screen.findByText('Confirmed threats · last 7 days')).toBeTruthy();
    await waitFor(() => {
      const sinces = getThreats.mock.calls.map((c) => Date.now() - Date.parse(c[0].since));
      expect(sinces.some((ms) => Math.abs(ms - 7 * 86_400_000) < 60_000)).toBe(true);
    });
  });

  // NEGATIVE CONTROL. The alert groups in the window do not decide the tile.
  // The outcomes chart still counts them, and states that unit.
  it('does not count alert groups', async () => {
    await mount();
    const tile = await tpTile();
    await waitFor(() => expect(screen.getByTestId('tp-total').textContent).toBe('15'));
    expect(tile.textContent).not.toContain('detection groups');
    expect(screen.getByTestId('outcomes-clock').textContent).toBe(
      'The chart counts the alert groups with an alert in this window.',
    );
  });

  it('states a failed read as unknown in the tile and in the panel', async () => {
    await mount();
    getThreats.mockReset().mockRejectedValue(new Error('503'));
    fireEvent.click(screen.getByText('7d'));
    await screen.findByTestId('confirmed-threats-error');
    const tile = (await screen.findByText('True positives that wait · 7d')).closest('.rounded-panel')!;
    expect(within(tile as HTMLElement).getByTestId('tp-total').textContent).toBe('?');
    expect(tile.textContent).toContain('Could not read the confirmed threats.');
    // NEGATIVE CONTROL: a failure is not a zero and not the empty line.
    expect(screen.queryByTestId('confirmed-threats-empty')).toBeNull();
  });

  it('labels the pipeline-error clause with its OWN window and unit', async () => {
    await mount([fallback('fb1'), fallback('fb2')]);
    const tile = await tpTile();
    // It counts investigation runs over thirty days, which is neither the unit
    // nor the window in the tile's heading, so it says so. The clause waits for
    // its own read.
    await waitFor(() => expect(tile.textContent).toMatch(/failed investigations · last 30 days/i));
    expect(await screen.findByRole('button', { name: '2 failed investigations' })).toBeTruthy();
  });

  it('says nothing about a 30-day window when there is nothing to say', async () => {
    await mount();
    const tile = await tpTile();
    expect(tile.textContent).not.toMatch(/30 days/);
  });
});

// Round "decide once" (DC3). Production at 7 days read "12 on 0 hosts", and the
// link opened 14 rows. Each of the 12 was in a closed campaign.
describe('Dashboard true-positives tile counts what waits', () => {
  it('states the waiting count and its machines, never the decided ones', async () => {
    await mount();
    getThreats.mockReset().mockResolvedValue({
      ...threatsOf(15),
      waiting: 3,
      waitingHosts: 2,
      decided: { campaigns: 1, investigations: 12 },
    });
    fireEvent.click(screen.getByText('7d'));
    const tile = (await screen.findByText('True positives that wait · 7d')).closest('.rounded-panel')!;
    await waitFor(() => expect(within(tile as HTMLElement).getByTestId('tp-total').textContent).toBe('3'));
    expect(within(tile as HTMLElement).getByTestId('tp-hosts').textContent).toBe('on 2 hosts in this window');
    // The panel header states the same count.
    expect(screen.getByTestId('confirmed-threats-total').textContent).toBe('3 true positives wait');
    expect(screen.getByTestId('threat-decided').textContent).toBe(
      'Decided: 1 campaign with 12 true positive investigations in this window.',
    );
  });

  it('states the split when a campaign with no decision holds some of them (OW2)', async () => {
    await mount();
    getThreats.mockReset().mockResolvedValue({
      ...threatsOf(6),
      waiting: 6,
      waitingHosts: 3,
      waitingInCampaigns: 2,
      waitingCampaigns: 1,
    });
    fireEvent.click(screen.getByText('7d'));
    const tile = (await screen.findByText('True positives that wait · 7d')).closest('.rounded-panel')!;
    await waitFor(() => expect(within(tile as HTMLElement).getByTestId('tp-total').textContent).toBe('6'));
    expect((await within(tile as HTMLElement).findByTestId('tp-split')).textContent).toBe(
      '6 true positives wait: 4 on their own, 2 in 1 campaign.',
    );
  });

  // Round 3 part 2 (W2): the close of a reopened campaign covered 28 of them.
  it('states the true positives that the close of a reopened campaign covered, and the panel states the same', async () => {
    await mount();
    getThreats.mockReset().mockResolvedValue({
      ...threatsOf(8),
      waiting: 8,
      waitingHosts: 2,
      waitingInCampaigns: 2,
      waitingCampaigns: 1,
      earlier: { campaigns: 1, investigations: 28, decision: 'closed', decidedAt: '2026-11-15T01:01:12Z' },
    });
    fireEvent.click(screen.getByText('30d'));
    const tile = (await screen.findByText('True positives that wait · 30d')).closest('.rounded-panel')!;
    await waitFor(() => expect(within(tile as HTMLElement).getByTestId('tp-total').textContent).toBe('8'));
    const words = '28 are in a campaign that opened again. The close of 2026-11-15 covered them.';
    expect((await within(tile as HTMLElement).findByTestId('tp-earlier')).textContent).toBe(words);
    expect(screen.getByTestId('threat-earlier').textContent).toBe(words);
  });

  it('control: the tile states no split when no campaign holds one', async () => {
    await mount();
    getThreats.mockReset().mockResolvedValue({ ...threatsOf(3), waiting: 3, waitingHosts: 2, waitingInCampaigns: 0 });
    fireEvent.click(screen.getByText('7d'));
    const tile = (await screen.findByText('True positives that wait · 7d')).closest('.rounded-panel')!;
    await waitFor(() => expect(within(tile as HTMLElement).getByTestId('tp-total').textContent).toBe('3'));
    expect(within(tile as HTMLElement).queryByTestId('tp-split')).toBeNull();
    expect(within(tile as HTMLElement).queryByTestId('tp-earlier')).toBeNull();
  });

  it('states no machine count under a count of 0', async () => {
    // NEGATIVE CONTROL: twelve decided true positives are no threat that waits.
    await mount();
    getThreats.mockReset().mockResolvedValue({
      ...threatsOf(12),
      rows: [],
      authorized: [],
      campaigns: [],
      waiting: 0,
      waitingHosts: 0,
      decided: { campaigns: 1, investigations: 12 },
    });
    fireEvent.click(screen.getByText('7d'));
    const tile = (await screen.findByText('True positives that wait · 7d')).closest('.rounded-panel')!;
    await waitFor(() => expect(within(tile as HTMLElement).getByTestId('tp-total').textContent).toBe('0'));
    expect(within(tile as HTMLElement).getByTestId('tp-hosts').textContent).toBe('None waits in this window.');
    expect(tile.textContent).not.toMatch(/on 0 hosts/);
    expect(screen.getByTestId('confirmed-threats-empty').textContent).toBe('No confirmed threat waits for a decision.');
  });
});
