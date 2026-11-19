// Confirmed threats (H1). The review of 2026-11-12 found the one result that
// needed a response 10,900 px down the Hunt Console, a Dashboard that stated
// two true positive counts and no host name, and a host page that listed
// three false positives first (ui-core 3, ui-hunt 1 and 7).
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getThreats: vi.fn(),
}));

import { getThreats, type ThreatCampaign, type ThreatList, type ThreatRow } from '../lib/api';
import { utcWindow } from '../lib/timeRange';
import { forbiddenWords } from '../test/analystWords';
import { THREAT_CAMPAIGN } from '../test/campaign';
import {
  ConfirmedThreats,
  HostThreatStrip,
  type ThreatsRead,
  authorizedLine,
  runsWords,
  sourcesWords,
  useThreats,
  waitingSplitWords,
} from './ConfirmedThreats';

const minutesAgo = (m: number) => new Date(Date.now() - m * 60_000).toISOString();

const row = (over: Partial<ThreatRow> = {}): ThreatRow => ({
  target: { address: '10.20.30.5', name: 'mainsrv', role: 'web server', machineKey: 'agent:m1' },
  direction: 'inbound',
  headline: 'An exploit chain ran against the web server and opened a shell.',
  impact: 'succeeded',
  runs: 12,
  alertRuns: 9,
  findingRuns: 3,
  sources: [
    { address: '10.40.50.7', name: 'kali01' },
    { address: '10.40.50.8', name: null },
  ],
  sourcesMore: 1,
  rules: ['ET EXPLOIT Example RCE'],
  rulesMore: 0,
  firstSeen: minutesAgo(600),
  lastSeen: minutesAgo(120),
  waitingActions: 2,
  newestInvestigationId: 'inv-new',
  investigationsHref: '/investigations?entity=agent%3Am1&verdict=true_positive&range=24h',
  ...over,
});

const LIST: ThreatList = {
  window: { since: minutesAgo(1440), until: minutesAgo(0) },
  rows: [
    row(),
    row({
      target: { address: '10.20.30.9', name: null, role: null, machineKey: null },
      headline: 'A scanner probed the file server.',
      impact: 'attempted',
      runs: 1,
      alertRuns: 1,
      findingRuns: 0,
      sources: [{ address: '10.40.50.7', name: 'kali01' }],
      sourcesMore: 0,
      waitingActions: 0,
      newestInvestigationId: 'inv-b',
      investigationsHref: '/investigations?entity=10.20.30.9&verdict=true_positive&range=24h',
    }),
    row({
      target: { address: '10.20.30.11', name: 'db01', role: null, machineKey: 'agent:db' },
      headline: 'A login brute force reached the database host.',
      impact: 'unknown',
      waitingActions: 0,
      investigationsHref: '/investigations?entity=agent%3Adb',
    }),
    row({
      target: { address: '10.20.30.12', name: 'print01', role: 'printer', machineKey: 'agent:pr' },
      headline: 'A known exploit hit a patched service.',
      impact: 'none',
      waitingActions: 0,
    }),
  ],
  authorized: [
    {
      authorization: { id: 7, label: 'Red team test', state: 'active', expiresAt: '2026-11-20T09:00:00' },
      target: { address: '10.20.30.20', name: 'lab01', role: null, machineKey: 'agent:lab' },
      direction: 'inbound',
      runs: 4,
      lastSeen: minutesAgo(30),
      runsHref: '/investigations?authorization=7&range=all',
    },
  ],
  total: 17,
};

/** A read in one fixed state, for the presentation tests. */
const readOf = (over: Partial<ThreatsRead> = {}): ThreatsRead => ({
  data: { key: 'k', list: LIST },
  loading: false,
  error: null,
  lastUpdated: Date.now(),
  failCount: 0,
  refetch: vi.fn(),
  ...over,
});

const panel = (read: ThreatsRead, windowLabel = 'last 24 hours') =>
  render(
    <MemoryRouter>
      <ConfirmedThreats read={read} readKey="k" windowLabel={windowLabel} />
    </MemoryRouter>,
  );

describe('ConfirmedThreats panel', () => {
  it('renders the rows in the order the server gives, each with its impact chip', () => {
    panel(readOf());
    const rows = screen.getAllByTestId('threat-row');
    expect(rows.map((r) => within(r).getByTestId('threat-target').textContent)).toEqual([
      'mainsrv (web server)',
      '10.20.30.9',
      'db01',
      'print01 (printer)',
    ]);
    const chips = rows.map((r) => within(r).getByTestId('impact-chip'));
    expect(chips.map((c) => c.textContent)).toEqual(['Succeeded', 'Attempted', 'Impact unknown', 'No impact']);
    // Only Succeeded and Attempted wear the danger and the warning tokens.
    expect(chips[0].className).toContain('text-danger');
    expect(chips[1].className).toContain('text-warn');
    for (const quiet of chips.slice(2)) {
      expect(quiet.className).not.toMatch(/text-danger|text-warn/);
      expect(quiet.className).toContain('text-dim');
    }
  });

  it('states the target, the headline, the sources, the count and the newest event', () => {
    panel(readOf());
    const first = screen.getAllByTestId('threat-row')[0];
    // The name and the role, with the address beside it.
    expect(first.textContent).toContain('mainsrv (web server)10.20.30.5');
    expect(within(first).getByTestId('threat-headline').textContent).toBe(LIST.rows[0].headline);
    expect(within(first).getByTestId('threat-meta').textContent).toBe(
      'From kali01, 10.40.50.8 +1 · 12 investigations: 9 alerts, 3 findings · Newest event 2h ago',
    );
    // The address alone when the host has no name.
    const second = screen.getAllByTestId('threat-row')[1];
    expect(within(second).getByTestId('threat-target').textContent).toBe('10.20.30.9');
    expect(within(second).getByTestId('threat-meta').textContent).toContain('1 investigation: 1 alert');
  });

  it('states "To" the external ends of an outbound row', () => {
    const outbound = row({
      direction: 'outbound',
      target: { address: '10.40.50.7', name: 'devbox', role: null, machineKey: 'agent:d1' },
      sources: [{ address: '203.0.113.50', name: null }],
      sourcesMore: 0,
      runs: 1,
      alertRuns: 1,
      findingRuns: 0,
    });
    panel(readOf({ data: { key: 'k', list: { ...LIST, rows: [outbound], authorized: [] } } }));
    const meta = within(screen.getByTestId('threat-row')).getByTestId('threat-meta');
    expect(meta.textContent).toMatch(/^To 203\.0\.113\.50 · 1 investigation: 1 alert/);
    expect(meta.textContent).not.toContain('From');
  });

  it('makes each row one link: the actions that wait, else the investigations', () => {
    panel(readOf());
    const rows = screen.getAllByTestId('threat-row');
    expect(rows.every((r) => r.tagName === 'A')).toBe(true);
    expect(rows[0].getAttribute('href')).toBe('/investigation/inv-new');
    expect(within(rows[0]).getByTestId('threat-primary').textContent).toBe('2 actions wait');
    expect(rows[1].getAttribute('href')).toBe(LIST.rows[1].investigationsHref);
    expect(within(rows[1]).getByTestId('threat-primary').textContent).toBe('Open');
    // One link for each row, and nothing else in the row takes the focus.
    for (const r of rows) expect(r.querySelectorAll('a, button').length).toBe(0);
  });

  it('says "1 action waits" for one action', () => {
    panel(readOf({ data: { key: 'k', list: { ...LIST, rows: [row({ waitingActions: 1 })] } } }));
    expect(screen.getByTestId('threat-primary').textContent).toBe('1 action waits');
  });

  it('puts one quiet line under the rows for each authorized group', () => {
    panel(readOf());
    const line = screen.getByTestId('threat-authorized');
    expect(line.textContent).toBe(
      'Authorized activity: Red team test. 4 investigations on lab01. Expires 2026-11-20 09:00 UTC.',
    );
    expect(line.getAttribute('href')).toBe('/investigations?authorization=7&range=all');
    // NEGATIVE CONTROL: an authorized group is not a threat row.
    expect(screen.getAllByTestId('threat-row')).toHaveLength(4);
    expect(screen.queryByText('lab01')).toBeNull();
  });

  it('states the authorized runs of a row in one quiet line under it, with a link', () => {
    // Polish review 2026-11-13: a row read "22 runs: 9 alerts, 13 findings"
    // and nothing said that 9 of them are inside an authorization.
    const mixed = row({
      runs: 22,
      alertRuns: 9,
      findingRuns: 13,
      authorizedRuns: 9,
      authorizations: [
        {
          id: 7,
          label: 'php2shell security testing',
          state: 'active',
          expiresAt: '2026-11-20T09:00:00+00:00',
          runs: 9,
          runsHref: '/investigations?authorization=7&range=all',
        },
      ],
    });
    panel(readOf({ data: { key: 'k', list: { ...LIST, rows: [mixed], authorized: [] } } }));
    const line = screen.getByTestId('threat-authorized-runs');
    expect(line.textContent).toBe('9 of 22 investigations are authorized activity: php2shell security testing.');
    const link = within(line).getByRole('link', { name: 'php2shell security testing' });
    expect(link.getAttribute('href')).toBe('/investigations?authorization=7&range=all');
    // The line sits outside the row link: no link inside a link.
    expect(screen.getByTestId('threat-row').contains(line)).toBe(false);
  });

  it('control: a row with no authorized run has no such line', () => {
    panel(readOf({ data: { key: 'k', list: { ...LIST, rows: [row({ authorizedRuns: 0, authorizations: [] })] } } }));
    expect(screen.queryByTestId('threat-authorized-runs')).toBeNull();
    panel(readOf({ data: { key: 'k', list: { ...LIST, rows: [row()] } } }));
    expect(screen.queryByTestId('threat-authorized-runs')).toBeNull();
  });

  it('states the total of the response in the header', () => {
    panel(readOf());
    expect(screen.getByTestId('confirmed-threats-title').textContent).toBe('Confirmed threats · last 24 hours');
    expect(screen.getByTestId('confirmed-threats-total').textContent).toBe('17 true positives');
  });

  it('states the split when a campaign with no decision holds some of the true positives that wait', () => {
    const list = { ...LIST, waiting: 6, waitingInCampaigns: 2, waitingCampaigns: 1 };
    panel(readOf({ data: { key: 'k', list } }));
    expect(screen.getByTestId('confirmed-threats-total').textContent).toBe(
      '6 true positives wait: 4 on their own, 2 in 1 campaign.',
    );
    expect(waitingSplitWords({ ...list, waitingInCampaigns: 3, waitingCampaigns: 2 })).toBe(
      '6 true positives wait: 3 on their own, 3 in 2 campaigns.',
    );
  });

  it('control: no campaign holds a true positive that waits, so the header states no split', () => {
    panel(readOf({ data: { key: 'k', list: { ...LIST, waiting: 6, waitingInCampaigns: 0, waitingCampaigns: 0 } } }));
    expect(screen.getByTestId('confirmed-threats-total').textContent).toBe('6 true positives wait');
  });

  it('states the window in the empty line, never a blank card', () => {
    panel(readOf({ data: { key: 'k', list: { ...LIST, rows: [], authorized: [], total: 0 } } }), 'last 7 days');
    expect(screen.getByTestId('confirmed-threats-empty').textContent).toBe('No confirmed threat in the last 7 days.');
    expect(screen.queryByTestId('confirmed-threats-error')).toBeNull();
  });

  it('keeps the authorized lines when no other row exists, and says what the empty line excludes', () => {
    panel(readOf({ data: { key: 'k', list: { ...LIST, rows: [] } } }));
    expect(screen.getByTestId('confirmed-threats-empty').textContent).toBe(
      'No confirmed threat outside authorized activity in the last 24 hours.',
    );
    expect(screen.getByTestId('threat-authorized')).toBeTruthy();
  });

  it('reads a failed read as a failure, not as no threat', () => {
    const refetch = vi.fn();
    panel(readOf({ data: null, error: new Error('503'), refetch }));
    const failed = screen.getByTestId('confirmed-threats-error');
    expect(failed.textContent).toContain('Could not read the confirmed threats. This is not an all-clear.');
    // NEGATIVE CONTROL: the empty sentence and a total never show on a failure.
    expect(screen.queryByTestId('confirmed-threats-empty')).toBeNull();
    expect(screen.queryByText(/No confirmed threat/)).toBeNull();
    expect(screen.queryByTestId('confirmed-threats-total')).toBeNull();
    fireEvent.click(within(failed).getByRole('button', { name: /Retry/ }));
    expect(refetch).toHaveBeenCalled();
  });

  it('shows a loading line, not the empty line, while the first read runs', () => {
    panel(readOf({ data: null, loading: true }));
    expect(screen.getByText('Reading the confirmed threats')).toBeTruthy();
    expect(screen.queryByTestId('confirmed-threats-empty')).toBeNull();
  });

  it('does not show the rows of another window while the new window loads', () => {
    panel(readOf({ data: { key: 'old-window', list: LIST }, loading: true }));
    expect(screen.queryAllByTestId('threat-row')).toHaveLength(0);
    expect(screen.getByText('Reading the confirmed threats')).toBeTruthy();
  });

  it('keeps the rows with a stale notice when a later read fails', () => {
    panel(readOf({ error: new Error('503') }));
    expect(screen.getAllByTestId('threat-row')).toHaveLength(4);
    expect(screen.getByText(/Refresh failed/)).toBeTruthy();
  });

  it('shows the five worst hosts first and the rest on request', () => {
    const many = Array.from({ length: 8 }, (_, i) =>
      row({ target: { address: `10.20.30.${40 + i}`, name: `host${i}`, role: null, machineKey: `agent:h${i}` } }),
    );
    panel(readOf({ data: { key: 'k', list: { ...LIST, rows: many } } }));
    const shown = () => screen.getAllByTestId('threat-target').map((t) => t.textContent);
    expect(shown()).toEqual(['host0', 'host1', 'host2', 'host3', 'host4']);
    const more = screen.getByTestId('confirmed-threats-more');
    expect(more.textContent).toBe('Show 3 more hosts');
    fireEvent.click(more);
    expect(shown()).toHaveLength(8);
    expect(screen.getByTestId('confirmed-threats-more').textContent).toBe('Show fewer hosts');
  });

  it('offers no "more" control for five rows or fewer', () => {
    panel(readOf());
    expect(screen.queryByTestId('confirmed-threats-more')).toBeNull();
  });

  // jsdom draws no layout, so this pins the classes that make the row wrap at
  // 1100 px: the row wraps, the text block can shrink, and long words break.
  it('wraps a row cleanly in a narrow window', () => {
    window.innerWidth = 1100;
    panel(
      readOf({
        data: {
          key: 'k',
          list: {
            ...LIST,
            rows: [row({ headline: 'A'.repeat(300), sources: Array.from({ length: 6 }, (_, i) => ({ address: `10.40.50.${i}`, name: `source-host-${i}` })) })],
          },
        },
      }),
    );
    const r = screen.getByTestId('threat-row');
    expect(r.className).toContain('flex-wrap');
    const body = r.firstElementChild as HTMLElement;
    expect(body.className).toContain('min-w-0');
    expect(within(r).getByTestId('threat-headline').className).toContain('break-words');
    expect(within(r).getByTestId('threat-meta').className).toContain('break-words');
    expect(within(r).getByTestId('threat-primary').className).toContain('flex-none');
  });
});

describe('ConfirmedThreats words', () => {
  it('counts the investigations by type', () => {
    expect(runsWords({ runs: 12, alertRuns: 9, findingRuns: 3 })).toBe('12 investigations: 9 alerts, 3 findings');
    expect(runsWords({ runs: 2, alertRuns: 0, findingRuns: 2 })).toBe('2 investigations: 2 findings');
  });

  it('names the sources and the rest as +N', () => {
    expect(sourcesWords([{ address: '10.40.50.7', name: 'kali01' }], 3)).toBe('kali01 +3');
    expect(sourcesWords([], 0)).toBe('');
  });

  it('states an expired authorization as expired', () => {
    expect(
      authorizedLine({ ...LIST.authorized[0], authorization: { ...LIST.authorized[0].authorization, state: 'expired' } }),
    ).toBe('Authorized activity: Red team test. 4 investigations on lab01. Expired 2026-11-20 09:00 UTC.');
  });
});

function HostMounted({ host }: { host: string }) {
  const read = useThreats(`host|${host}`, () =>
    host ? { since: new Date(Date.now() - 30 * 86_400_000).toISOString(), host } : null,
  );
  return <HostThreatStrip read={read} readKey={`host|${host}`} />;
}

const hostStrip = (host = 'agent:m1') =>
  render(
    <MemoryRouter>
      <HostMounted host={host} />
    </MemoryRouter>,
  );

describe('HostThreatStrip', () => {
  beforeEach(() => {
    vi.mocked(getThreats).mockReset();
  });

  it('states the group of the host, its impact, its headline and the waiting action', async () => {
    vi.mocked(getThreats).mockResolvedValue({ ...LIST, rows: [row()], authorized: [], total: 12 });
    hostStrip();
    const strip = await screen.findByTestId('host-threats');
    expect(within(strip).getByTestId('host-threats-count').textContent).toBe(
      'This host has 12 true positive investigations in the last 30 days.',
    );
    expect(within(strip).getByTestId('impact-chip').textContent).toBe('Succeeded');
    expect(strip.textContent).toContain(LIST.rows[0].headline);
    expect(strip.textContent).toContain('9 alerts, 3 findings');
    const link = within(strip).getByTestId('host-threats-primary');
    expect(link.textContent).toBe('2 actions wait');
    expect(link.getAttribute('href')).toBe('/investigation/inv-new');
    // The read names the host and a 30 day window.
    const q = vi.mocked(getThreats).mock.calls[0][0];
    expect(q.host).toBe('agent:m1');
    expect(Math.abs(Date.now() - Date.parse(q.since) - 30 * 86_400_000)).toBeLessThan(60_000);
  });

  it('shows nothing when the host has no row', async () => {
    vi.mocked(getThreats).mockResolvedValue({ ...LIST, rows: [], authorized: [], total: 0 });
    const { container } = hostStrip();
    await waitFor(() => expect(getThreats).toHaveBeenCalled());
    await waitFor(() => expect(container.textContent).toBe(''));
    expect(screen.queryByTestId('host-threats')).toBeNull();
  });

  it('says that the read failed, so a failure does not read as a clean host', async () => {
    vi.mocked(getThreats).mockRejectedValue(new Error('offline'));
    hostStrip();
    expect((await screen.findByTestId('confirmed-threats-error')).textContent).toContain(
      'Could not read the confirmed threats of this host. This is not an all-clear.',
    );
    expect(screen.queryByTestId('host-threats')).toBeNull();
  });

  it('reads nothing before the page knows the host', async () => {
    const { container } = hostStrip('');
    await new Promise((r) => setTimeout(r, 0));
    expect(getThreats).not.toHaveBeenCalled();
    expect(container.textContent).toBe('');
  });
});

// The campaign is the unit of work (owner, 2026-11-14). The campaigns of the
// window lead the panel, and the other true positives stay below them.
describe('ConfirmedThreats campaigns', () => {
  const withCampaigns = (campaigns: ThreatCampaign[], over: Partial<ThreatList> = {}) =>
    readOf({ data: { key: 'k', list: { ...LIST, campaigns, ...over } } });

  it('leads the panel with the campaign rows, and puts the other rows under a plain label', () => {
    panel(withCampaigns([THREAT_CAMPAIGN, { ...THREAT_CAMPAIGN, id: 8, title: 'actor-b against db01', stage: null }]));
    const campaigns = screen.getAllByTestId('threat-campaign');
    expect(campaigns.map((c) => within(c).getByTestId('threat-campaign-title').textContent)).toEqual([
      'actor-a against web-1',
      'actor-b against db01',
    ]);
    const label = screen.getByTestId('threat-others-label');
    expect(label.textContent).toBe('Not in a campaign');
    const first = screen.getAllByTestId('threat-row')[0];
    const follows = (a: Node, b: Node) => Boolean(a.compareDocumentPosition(b) & Node.DOCUMENT_POSITION_FOLLOWING);
    expect(follows(campaigns[1], label)).toBe(true);
    expect(follows(label, first)).toBe(true);
    // The total of the window does not change.
    expect(screen.getByTestId('confirmed-threats-total').textContent).toBe('17 true positives');
  });

  it('states the stage, the title, the status, the machines, the alerts, the period and the decisions', () => {
    panel(withCampaigns([THREAT_CAMPAIGN]));
    const c = screen.getByTestId('threat-campaign');
    expect(within(c).getByRole('img')).toHaveAccessibleName('Stage reached: Action on the target, 4 of 5');
    expect(within(c).getByRole('link', { name: 'actor-a against web-1' })).toHaveAttribute('href', '/campaigns/7');
    expect(within(c).getByTestId('campaign-state').textContent).toBe('Open');
    expect(within(c).getByTestId('threat-campaign-parties').textContent).toBe('From actor-a to web-1');
    expect(within(c).getByRole('link', { name: 'web-1' })).toHaveAttribute('href', '/hosts/net%3A192.0.2.20');
    expect(within(c).getByTestId('threat-campaign-meta').textContent).toBe(
      `47 alerts · ${utcWindow(THREAT_CAMPAIGN.firstEvent, THREAT_CAMPAIGN.lastEvent)}`,
    );
    // The campaign waits, and its investigations do not: the decision chip
    // states it, and no line counts investigations that wait.
    expect(within(c).queryByTestId('threat-campaign-waiting')).toBeNull();
    expect(c.textContent).not.toMatch(/on a decision/);
    expect(within(c).getByTestId('threat-campaign-authorized').textContent).toBe('4 authorized');
    // The texts wrap. None is cut.
    expect(within(c).getByTestId('threat-campaign-title').className).toContain('break-words');
    expect(within(c).getByTestId('threat-campaign-parties').className).toContain('break-words');
  });

  it('states one state chip for each campaign, never Open beside Closed', () => {
    panel(
      withCampaigns([
        { ...THREAT_CAMPAIGN, decision: null, waitsSince: '2026-10-24T00:40:00Z', state: 'open' },
        { ...THREAT_CAMPAIGN, id: 8, title: 'actor-b against db01', decision: 'closed', waitsSince: null, state: 'closed' },
      ]),
    );
    const [waits, closed] = screen.getAllByTestId('threat-campaign');
    const chip = within(waits).getByTestId('campaign-state');
    expect(chip.textContent).toBe('Open');
    expect(chip).toHaveAttribute('data-waits', 'true');
    expect(within(closed).getAllByTestId('campaign-state').map((c) => c.textContent)).toEqual(['Closed']);
    expect(within(closed).queryByText('Open')).toBeNull();
  });

  it('states a campaign with a case as Case', () => {
    panel(withCampaigns([{ ...THREAT_CAMPAIGN, decision: 'case', waitsSince: null }]));
    const c = screen.getByTestId('threat-campaign');
    const chip = within(c).getByTestId('campaign-state');
    expect(chip.textContent).toBe('Case');
    expect(chip).toHaveAttribute('title', 'A Security Onion case holds this campaign.');
    expect(forbiddenWords(c)).toEqual([]);
  });

  it('states the expiry in the hover text of the Authorized chip and the investigations beyond the authorization in the danger tone', () => {
    const expiresAt = new Date(Date.now() + 7 * 86_400_000).toISOString();
    panel(
      withCampaigns([
        {
          ...THREAT_CAMPAIGN,
          decision: 'authorized',
          waitsSince: null,
          authorization: { expiresAt, state: 'active' },
          beyond: 2,
          waiting: 5,
        },
      ]),
    );
    const c = screen.getByTestId('threat-campaign');
    expect(within(c).getByTestId('campaign-state').textContent).toBe('Authorized');
    expect(within(c).getByTestId('campaign-state').getAttribute('title')).toMatch(/^An authorization covers this campaign until /);
    const beyond = within(c).getByTestId('campaign-beyond-chip');
    // The line reads `beyond`, never `waiting`.
    expect(beyond.textContent).toBe('2 beyond the authorization');
    expect(beyond.className).toContain('text-danger');
    expect(forbiddenWords(c)).toEqual([]);
  });

  it('states an expired authorization in the past tense', () => {
    panel(
      withCampaigns([
        { ...THREAT_CAMPAIGN, decision: 'authorized', authorization: { expiresAt: '2026-11-01T09:00:00Z', state: 'expired' } },
      ]),
    );
    expect(screen.getByTestId('campaign-state').getAttribute('title')).toBe(
      'The authorization of this campaign expired 2026-11-01 09:00 UTC, and a later event waits on you.',
    );
  });

  it('states no beyond alarm with a count of 0, and reads an older server as before', () => {
    // NEGATIVE CONTROLS: no count, no alarm; an older server sends neither field.
    panel(
      withCampaigns([
        { ...THREAT_CAMPAIGN, decision: 'authorized', authorization: null, beyond: 0, waiting: 3 },
        { ...THREAT_CAMPAIGN, id: 8, decision: 'authorized', waiting: 3 },
      ]),
    );
    expect(screen.queryByTestId('campaign-beyond-chip')).toBeNull();
    expect(screen.getAllByTestId('campaign-state').map((c) => c.textContent)).toEqual(['Authorized', 'Authorized']);
  });

  it('claims no wait for a server that sends no decision', () => {
    // NEGATIVE CONTROL. An absent field is no "waits": the console claims nothing.
    panel(withCampaigns([THREAT_CAMPAIGN]));
    expect(screen.getByTestId('campaign-state')).toHaveAttribute('data-waits', 'false');
  });

  it('names the further targets and the investigations when the alerts are unknown', () => {
    panel(withCampaigns([{ ...THREAT_CAMPAIGN, targetsMore: 4, alerts: null, waiting: 1 }]));
    const c = screen.getByTestId('threat-campaign');
    expect(within(c).getByTestId('threat-campaign-parties').textContent).toBe('From actor-a to web-1 and 4 more');
    expect(within(c).getByTestId('threat-campaign-meta').textContent).toMatch(/^25 true positive investigations · /);
    expect(within(c).queryByTestId('threat-campaign-waiting')).toBeNull();
  });

  // NEGATIVE CONTROL. A count of 0 states nothing.
  it('states no decision and no authorization when the counts are 0', () => {
    panel(withCampaigns([{ ...THREAT_CAMPAIGN, waiting: 0, authorized: 0 }]));
    expect(screen.queryByTestId('threat-campaign-waiting')).toBeNull();
    expect(screen.queryByTestId('threat-campaign-authorized')).toBeNull();
  });

  it('shows no empty line when every true positive is in a campaign', () => {
    panel(withCampaigns([THREAT_CAMPAIGN], { rows: [], authorized: [] }));
    expect(screen.getByTestId('threat-campaign')).toBeTruthy();
    expect(screen.queryByTestId('confirmed-threats-empty')).toBeNull();
    expect(screen.queryByTestId('threat-others-label')).toBeNull();
  });

  // NEGATIVE CONTROL. A server of an earlier release sends no campaigns: the
  // panel is the panel of before, with no label.
  it('shows the rows with no label when the server sends no campaign', () => {
    panel(readOf());
    expect(screen.queryByTestId('threat-campaign')).toBeNull();
    expect(screen.queryByTestId('threat-others-label')).toBeNull();
    panel(withCampaigns([]));
    expect(screen.queryByTestId('threat-others-label')).toBeNull();
  });

  it('holds no forbidden word in the panel', () => {
    const mixed = row({
      authorizedRuns: 2,
      authorizations: [
        { id: 7, label: 'Red team test', state: 'active', expiresAt: '2026-11-20T09:00:00Z', runs: 2, runsHref: '/x' },
      ],
    });
    const { container } = panel(withCampaigns([THREAT_CAMPAIGN], { rows: [mixed, ...LIST.rows] }));
    expect(forbiddenWords(container)).toEqual([]);
  });
});

describe('HostThreatStrip with campaigns', () => {
  beforeEach(() => {
    vi.mocked(getThreats).mockReset();
  });

  it('counts the investigations outside a campaign when the host is in a campaign', async () => {
    vi.mocked(getThreats).mockResolvedValue({
      ...LIST,
      campaigns: [THREAT_CAMPAIGN],
      rows: [row()],
      authorized: [],
      total: 37,
    });
    hostStrip();
    const strip = await screen.findByTestId('host-threats');
    expect(within(strip).getByTestId('host-threats-count').textContent).toBe(
      'This host has 12 true positive investigations outside a campaign in the last 30 days.',
    );
    expect(forbiddenWords(strip)).toEqual([]);
  });
});

// Round "decide once" (DC2, DC3). A campaign that the analyst closed stayed in
// the red list, and the header counted its true positives as threats.
describe('ConfirmedThreats with decided campaigns', () => {
  const decidedList = (over: Partial<ThreatList> = {}): ThreatList => ({
    ...LIST,
    rows: [],
    authorized: [],
    campaigns: [],
    total: 14,
    waiting: 0,
    waitingHosts: 0,
    decided: { campaigns: 1, investigations: 12 },
    ...over,
  });

  it('states that nothing waits, then one quiet line for the decided campaigns', () => {
    panel(readOf({ data: { key: 'k', list: decidedList() } }), 'last 7 days');
    expect(screen.getByTestId('confirmed-threats-total').textContent).toBe('0 true positives wait');
    expect(screen.getByTestId('confirmed-threats-empty').textContent).toBe('No confirmed threat waits for a decision.');
    const line = screen.getByTestId('threat-decided');
    expect(line.textContent).toBe('Decided: 1 campaign with 12 true positive investigations in this window.');
    // N15: the line counts the window, and the list holds every decided
    // campaign. The link says so.
    const link = screen.getByTestId('threat-decided-link');
    expect(link.textContent).toBe('Open all decided campaigns.');
    expect(link).toHaveAttribute('href', '/campaigns?decision=decided');
    expect(line).not.toHaveAttribute('href');
    expect(line.className).not.toMatch(/danger|warn/);
    expect(link.className).not.toMatch(/danger|warn/);
    // The decided line comes after the empty line.
    const empty = screen.getByTestId('confirmed-threats-empty');
    expect(empty.compareDocumentPosition(line) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(forbiddenWords(screen.getByTestId('confirmed-threats'))).toEqual([]);
  });

  it('keeps a campaign with no decision in the red list and counts what waits', () => {
    // NEGATIVE CONTROL: the server lists the campaign, and the panel shows it.
    panel(
      readOf({
        data: {
          key: 'k',
          list: decidedList({
            campaigns: [{ ...THREAT_CAMPAIGN, decision: null, state: 'open' }],
            waiting: 3,
            waitingHosts: 1,
            decided: { campaigns: 0, investigations: 0 },
          }),
        },
      }),
    );
    expect(screen.getByTestId('confirmed-threats-total').textContent).toBe('3 true positives wait');
    expect(screen.getAllByTestId('threat-campaign')).toHaveLength(1);
    // The line is absent at 0.
    expect(screen.queryByTestId('threat-decided')).toBeNull();
    expect(screen.queryByTestId('threat-decided-link')).toBeNull();
    expect(screen.queryByTestId('confirmed-threats-empty')).toBeNull();
  });

  it('states one waiting true positive in the singular', () => {
    panel(readOf({ data: { key: 'k', list: decidedList({ waiting: 1, rows: [row()] }) } }));
    expect(screen.getByTestId('confirmed-threats-total').textContent).toBe('1 true positive waits');
    expect(screen.getByTestId('threat-decided').textContent).toBe(
      'Decided: 1 campaign with 12 true positive investigations in this window.',
    );
  });
});

// Round 3 part 2 (W2). The Dashboard at 30 days read "36 true positives
// wait: 6 on their own, 30 in 1 campaign". The close of the campaign had
// covered 28 of the 30. The server takes them out of the count that waits.
describe('ConfirmedThreats with a campaign that opened again', () => {
  const reopenedList = (over: Partial<ThreatList> = {}): ThreatList => ({
    ...LIST,
    rows: [],
    authorized: [],
    campaigns: [{ ...THREAT_CAMPAIGN, decision: null, state: 'open' }],
    total: 36,
    waiting: 8,
    waitingHosts: 2,
    waitingInCampaigns: 2,
    waitingCampaigns: 1,
    decided: { campaigns: 0, investigations: 0 },
    earlier: { campaigns: 1, investigations: 28, decision: 'closed', decidedAt: '2026-11-15T01:01:12Z' },
    ...over,
  });

  it('states the count that waits and the true positives that the close covered', () => {
    panel(readOf({ data: { key: 'k', list: reopenedList() } }));
    expect(screen.getByTestId('confirmed-threats-total').textContent).toBe(
      '8 true positives wait: 6 on their own, 2 in 1 campaign.',
    );
    const line = screen.getByTestId('threat-earlier');
    expect(line.textContent).toBe('28 are in a campaign that opened again. The close of 2026-11-15 covered them.');
    expect(line.className).not.toMatch(/danger|warn/);
    expect(forbiddenWords(screen.getByTestId('confirmed-threats'))).toEqual([]);
  });

  it('states no such line when no earlier decision covers a true positive', () => {
    // NEGATIVE CONTROL: an older server, or a campaign that never had a decision.
    panel(readOf({ data: { key: 'k', list: reopenedList({ earlier: undefined }) } }));
    expect(screen.queryByTestId('threat-earlier')).toBeNull();
    panel(
      readOf({
        data: {
          key: 'k',
          list: reopenedList({ earlier: { campaigns: 0, investigations: 0, decision: null, decidedAt: null } }),
        },
      }),
    );
    expect(screen.queryByTestId('threat-earlier')).toBeNull();
  });
});
