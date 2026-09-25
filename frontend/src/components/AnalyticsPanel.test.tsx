// The Analytics tab. The status word is the column that was missing: a
// retired analytic and a quiet live one render the same row of zeros without
// it. The actions differ by status for the same reason, so a candidate can
// only be put in shadow and a shadow analytic can only be approved or
// rejected.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAnalytics: vi.fn(),
  getAnalytic: vi.fn(),
  getHuntCatalog: vi.fn(),
  setAnalyticStatus: vi.fn(),
  createAnalytic: vi.fn(),
  startHuntConsole: vi.fn(),
}));

import {
  getAnalytic,
  getAnalytics,
  getHuntCatalog,
  type AnalyticDetail,
  type AnalyticRow,
} from '../lib/api';
import { ShellProvider } from '../shell/ShellContext';
import { AnalyticsPanel } from './AnalyticsPanel';

const base = {
  level: 'high',
  evaluator: 'match',
  scope_kind: 'host',
  no_benign_baseline: false,
  observations_7d: 0,
  leads_7d: 0,
  hunted_7d: 0,
  dismissed_7d: 0,
  shadow_hits_7d: 0,
  unread_shadow_hits: 0,
};

const SHIPPED_LIVE: AnalyticRow = {
  ...base,
  id: 'identity-4662-dcsync-nonmachine',
  title: 'A non-machine account reads directory replication rights',
  tier: 'shipped',
  status: 'live',
  no_benign_baseline: true,
  observations_7d: 12,
  leads_7d: 1,
  hunted_7d: 1,
};

const LOCAL_SHADOW: AnalyticRow = {
  ...base,
  id: 'local-svc-ticket',
  title: 'A Kerberos ticket request names a service account from a workstation',
  tier: 'local',
  status: 'shadow',
  shadow_hits_7d: 3,
  unread_shadow_hits: 2,
};

const LOCAL_CANDIDATE: AnalyticRow = {
  ...base,
  id: 'local-rare-parent',
  title: 'A rare parent process starts a shell',
  tier: 'local',
  status: 'candidate',
};

const DETAIL: AnalyticDetail = {
  ...SHIPPED_LIVE,
  description: 'The analytic reads event 4662 and the replication rights it names.',
  spec_text: 'id: identity-4662-dcsync-nonmachine\n',
  reason: null,
  ledger: {
    analytic_id: SHIPPED_LIVE.id,
    since: new Date(Date.now() - 30 * 86_400_000).toISOString(),
    observations: 61,
    entities: 9,
    shadow_hits: 0,
    unread_shadow_hits: 0,
    leads: 4,
    hunted: 2,
    promoted: 1,
    dismissed: {},
    docs_scanned: 1200,
    runtime_ms: 900,
    sweeps: 30,
    coverage: {},
  },
  versions: [],
  recent: [],
};

/** The address bar, so a test can read what the drawer wrote there. */
function LocationProbe() {
  const l = useLocation();
  return <div data-testid="loc">{l.pathname + l.search}</div>;
}

const mount = (at = '/hunts?tab=analytics') =>
  render(
    <MemoryRouter initialEntries={[at]}>
      <ShellProvider>
        <AnalyticsPanel />
        <LocationProbe />
      </ShellProvider>
    </MemoryRouter>,
  );

beforeEach(() => {
  vi.mocked(getAnalytics).mockReset().mockResolvedValue({
    analytics: [SHIPPED_LIVE, LOCAL_SHADOW, LOCAL_CANDIDATE],
    counts: { live: 1, shadow: 1, candidate: 1 },
  });
  vi.mocked(getAnalytic).mockReset().mockResolvedValue(DETAIL);
  vi.mocked(getHuntCatalog).mockReset().mockResolvedValue({
    specs: [],
    sweeps_enabled: true,
    sweep_interval_minutes: 60,
    sweep_window_minutes: 61,
    last_sweep_at: null,
  });
});

describe('AnalyticsPanel', () => {
  it('states the counts and the legend', async () => {
    mount();
    await screen.findByText(/3 analytics · 1 live · 1 shadow · 1 candidate · 0 retired/);
    // Each status says what the sweep does and what happens to what it finds.
    // "runs, recorded, not raised" named neither actor.
    const legend = screen.getByTestId('analytics-legend');
    expect(legend.textContent).toContain('live: the sweep runs it and raises what it finds.');
    expect(legend.textContent).toContain('shadow: the sweep runs it and records what it finds.');
    expect(legend.textContent).toContain('candidate: the sweep has never run it.');
    expect(legend.textContent).toContain('retired: the analytic keeps its ledger and its reason.');
  });

  // Two analytics on one subject read the same from the title alone, and the
  // id is what an objective and a CLI call need.
  it('puts the analytic id under every title, in the mono face', async () => {
    mount();
    const row = await screen.findByTestId(`analytic-${SHIPPED_LIVE.id}`);
    const id = within(row).getByText(SHIPPED_LIVE.id);
    expect(id.className).toContain('font-mono');
  });

  it('keeps the action buttons on one line and widens the column at lg', async () => {
    mount();
    const row = await screen.findByTestId(`analytic-${LOCAL_SHADOW.id}`);
    expect(within(row).getByRole('button', { name: 'Approve' }).className).toContain(
      'whitespace-nowrap',
    );
    const actions = screen.getByText('Actions');
    expect(actions.className).toContain('lg:w-[210px]');
  });

  it('gives every row its status word and its tier', async () => {
    mount();
    const live = await screen.findByTestId(`analytic-${SHIPPED_LIVE.id}`);
    expect(within(live).getByText('live')).toBeTruthy();
    expect(within(live).getByText('shipped')).toBeTruthy();
    const shadow = screen.getByTestId(`analytic-${LOCAL_SHADOW.id}`);
    expect(within(shadow).getByText('shadow')).toBeTruthy();
    expect(within(shadow).getByText('local')).toBeTruthy();
    expect(within(shadow).getByText(/3 shadow hits · 2 unread/)).toBeTruthy();
  });

  it('offers the actions the status allows and no others', async () => {
    mount();
    const shadow = await screen.findByTestId(`analytic-${LOCAL_SHADOW.id}`);
    expect(within(shadow).getByRole('button', { name: 'Approve' })).toBeTruthy();
    expect(within(shadow).getByRole('button', { name: 'Reject' })).toBeTruthy();
    expect(within(shadow).queryByRole('button', { name: 'Run in shadow' })).toBeNull();

    const candidate = screen.getByTestId(`analytic-${LOCAL_CANDIDATE.id}`);
    expect(within(candidate).getByRole('button', { name: 'Run in shadow' })).toBeTruthy();
    expect(within(candidate).queryByRole('button', { name: 'Approve' })).toBeNull();

    const live = screen.getByTestId(`analytic-${SHIPPED_LIVE.id}`);
    expect(within(live).getByRole('button', { name: 'Hunt with this' })).toBeTruthy();
    expect(within(live).getByRole('button', { name: 'Retire' })).toBeTruthy();
  });

  it('opens the drawer on the analytic title', async () => {
    mount();
    const live = await screen.findByTestId(`analytic-${SHIPPED_LIVE.id}`);
    fireEvent.click(within(live).getByRole('button', { name: SHIPPED_LIVE.title }));
    await waitFor(() => expect(getAnalytic).toHaveBeenCalledWith(SHIPPED_LIVE.id));
    expect(await screen.findByText('Outcome ledger · last 30 days')).toBeTruthy();
  });

  // The same drawer opened from a lead page link lives in the address and
  // survives a reload. Opened from a title it did not, so a reload closed it
  // and the address described a screen the analyst was not looking at.
  it('writes the analytic it opened into the address, and takes it out again', async () => {
    mount();
    const live = await screen.findByTestId(`analytic-${SHIPPED_LIVE.id}`);
    fireEvent.click(within(live).getByRole('button', { name: SHIPPED_LIVE.title }));
    await waitFor(() =>
      expect(screen.getByTestId('loc').textContent).toBe(
        `/hunts?tab=analytics&open=${SHIPPED_LIVE.id}`,
      ),
    );

    fireEvent.keyDown(window, { key: 'Escape' });
    await waitFor(() => expect(screen.getByTestId('loc').textContent).toBe('/hunts?tab=analytics'));
  });

  it('opens the analytic the address names', async () => {
    mount(`/hunts?tab=analytics&open=${SHIPPED_LIVE.id}`);
    await waitFor(() => expect(getAnalytic).toHaveBeenCalledWith(SHIPPED_LIVE.id));
    expect(await screen.findByRole('dialog')).toBeTruthy();
  });
});


// The coverage column spoke for a sweep it never named, and a row that is
// blind on that sweep read as an analytic that found nothing.
describe('AnalyticsPanel sweep', () => {
  const SWEPT = {
    specs: [
      {
        id: SHIPPED_LIVE.id,
        title: SHIPPED_LIVE.title,
        level: 'high',
        coverage: {
          last_run_at: new Date(Date.now() - 3_600_000).toISOString(),
          measured: 6,
          learning: 0,
          blind: 38,
          not_applicable: 0,
          fired: 0,
          shadow: false,
        },
        last_swept_at: new Date(Date.now() - 600_000).toISOString(),
        last_fired_at: null,
        blind: true,
        last_error: null,
        sweeps_24h: 24,
        fired_24h: 0,
      },
    ],
    sweeps_enabled: true,
    sweep_interval_minutes: 60,
    sweep_window_minutes: 61,
    last_sweep_at: new Date(Date.now() - 600_000).toISOString(),
  };

  it('names the sweep the coverage column speaks for', async () => {
    vi.mocked(getHuntCatalog).mockResolvedValue(SWEPT as never);
    mount();
    const line = await screen.findByTestId('analytics-sweep');
    expect(line.textContent).toBe('last sweep 10m ago · window 61 min');
  });

  it('says never when no sweep has run', async () => {
    mount();
    const line = await screen.findByTestId('analytics-sweep');
    expect(line.textContent).toBe('last sweep never · window 61 min');
  });

  it('marks a row the newest sweep could not see', async () => {
    vi.mocked(getHuntCatalog).mockResolvedValue(SWEPT as never);
    mount();
    const row = await screen.findByTestId(`analytic-${SHIPPED_LIVE.id}`);
    expect(within(row).getByText('blind on the last sweep')).toBeTruthy();
    const quiet = screen.getByTestId(`analytic-${LOCAL_SHADOW.id}`);
    expect(within(quiet).queryByText('blind on the last sweep')).toBeNull();
  });

  // The coverage counts implied "now". On the range they were scored
  // against baselines three days old, and on production against a table
  // where two dimensions could not be measured at all.
  const withBaseline = (extra: Record<string, unknown>) => ({
    ...SWEPT,
    specs: [{ ...SWEPT.specs[0], coverage: { ...SWEPT.specs[0].coverage, ...extra } }],
  });

  it('says how old the baseline the coverage was scored against is', async () => {
    vi.mocked(getHuntCatalog).mockResolvedValue(
      withBaseline({
        profiles_built_at: new Date(Date.now() - 26 * 3_600_000).toISOString(),
        profiles_stale: true,
        profiles_reason: null,
      }) as never,
    );
    mount();
    const row = await screen.findByTestId(`analytic-${SHIPPED_LIVE.id}`);
    expect(within(row).getByText('6 measured · 38 blind · baseline 26 h old, stale')).toBeTruthy();
  });

  it('says why the baseline could not be measured', async () => {
    vi.mocked(getHuntCatalog).mockResolvedValue(
      withBaseline({
        profiles_built_at: new Date(Date.now() - 3_600_000).toISOString(),
        profiles_stale: false,
        profiles_reason: 'active_hours: Trying to create too many buckets',
      }) as never,
    );
    mount();
    const row = await screen.findByTestId(`analytic-${SHIPPED_LIVE.id}`);
    expect(
      within(row).getByText(
        '6 measured · 38 blind · baseline unmeasurable: active_hours: Trying to create too many buckets',
      ),
    ).toBeTruthy();
  });

  it('reads an older backend without baseline fields unchanged', async () => {
    vi.mocked(getHuntCatalog).mockResolvedValue(SWEPT as never);
    mount();
    const row = await screen.findByTestId(`analytic-${SHIPPED_LIVE.id}`);
    expect(within(row).getByText('6 measured · 38 blind')).toBeTruthy();
  });

  it('names a rejection in the legend', async () => {
    mount();
    const legend = await screen.findByTestId('analytics-legend');
    expect(legend.textContent).toContain('Rejected = retired with a reason.');
  });
});

// The owner asked for the list to filter on criteria. Each filter lives in
// the address bar, so a link carries it and a reload keeps it.
describe('AnalyticsPanel filters', () => {
  const rowIds = () =>
    screen
      .getAllByTestId(/^analytic-(?!blind-)/)
      .map((el) => el.getAttribute('data-testid')?.replace('analytic-', ''));

  it('filters on the status chip and states the match count', async () => {
    mount();
    await screen.findByTestId(`analytic-${SHIPPED_LIVE.id}`);
    fireEvent.click(screen.getByRole('button', { name: /^Shadow/ }));
    await waitFor(() => expect(rowIds()).toEqual([LOCAL_SHADOW.id]));
    expect(screen.getByTestId('analytics-counts').textContent).toContain(
      '1 of 3 analytics match',
    );
  });

  it('reads the filter from the address', async () => {
    mount('/hunts?tab=analytics&status=candidate');
    await screen.findByTestId(`analytic-${LOCAL_CANDIDATE.id}`);
    expect(rowIds()).toEqual([LOCAL_CANDIDATE.id]);
  });

  it('searches the title and the id', async () => {
    mount();
    await screen.findByTestId(`analytic-${SHIPPED_LIVE.id}`);
    const box = screen.getByPlaceholderText('Search title or id…');
    fireEvent.change(box, { target: { value: 'rare-parent' } });
    await waitFor(() => expect(rowIds()).toEqual([LOCAL_CANDIDATE.id]));
    fireEvent.change(box, { target: { value: 'kerberos' } });
    await waitFor(() => expect(rowIds()).toEqual([LOCAL_SHADOW.id]));
  });

  it('filters on the tier and offers only the tiers the list carries', async () => {
    mount();
    await screen.findByTestId(`analytic-${SHIPPED_LIVE.id}`);
    const tier = screen.getByRole('combobox', { name: 'Tier' });
    expect([...tier.querySelectorAll('option')].map((o) => o.textContent)).toEqual([
      'tier: any',
      'local',
      'shipped',
    ]);
    fireEvent.change(tier, { target: { value: 'local' } });
    await waitFor(() => expect(rowIds()).toEqual([LOCAL_SHADOW.id, LOCAL_CANDIDATE.id]));
  });

  it('says when nothing matches and clears the filters from there', async () => {
    mount('/hunts?tab=analytics&status=retired&tier=local');
    expect(await screen.findByText('No analytic matches these filters.')).toBeTruthy();
    // One in the toolbar, one in the empty state. Either clears.
    fireEvent.click(screen.getAllByRole('button', { name: 'Clear filters' })[1]);
    await waitFor(() => expect(rowIds()).toHaveLength(3));
    expect(screen.getByTestId('analytics-counts').textContent).toContain('3 analytics');
    expect(screen.queryByRole('button', { name: 'Clear filters' })).toBeNull();
  });

  it('keeps only the analytics active in the last 7 days', async () => {
    mount();
    await screen.findByTestId(`analytic-${SHIPPED_LIVE.id}`);
    fireEvent.click(screen.getByRole('checkbox', { name: /active in 7 days/ }));
    await waitFor(() => expect(rowIds()).toEqual([SHIPPED_LIVE.id]));
  });
});
