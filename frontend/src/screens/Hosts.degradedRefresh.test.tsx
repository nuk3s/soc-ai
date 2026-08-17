// A blind network sweep must not render as a quiet one.
//
// Degraded-grid sweep, 2026-08-13: the refresh status carries the sweep's
// `errors` list, and this screen read only `hosts_built` and `fields_written`
// out of it. With Security Onion unreachable the sweep builds nothing, writes
// nothing, and returns the same counters a settled network returns — so the
// screen printed a calm "Last sweep: 0 hosts built", or on a total failure
// (which carries no counters at all) printed nothing whatsoever, over a host
// list that was missing every machine the sweep could not reach.
//
// The counters cannot carry that difference, so these tests pin it to `errors`
// and to nothing else: not to a zero count (an estate where nothing changed
// builds zero hosts, correctly) and not to `notes` (advisory lines a HEALTHY
// sweep emits — a badge on those is a badge every night, which is how an
// operator learns to stop reading it).
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { DossierList, DossierRefreshStatus, DossierSummary } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  listDossiers: vi.fn(),
  getDossierConflicts: vi.fn(),
  getDossierSummary: vi.fn(),
  getDossierRefreshStatus: vi.fn(),
  startDossierRefresh: vi.fn(),
  getMe: vi.fn(),
}));

import {
  getDossierConflicts,
  getDossierRefreshStatus,
  getDossierSummary,
  getMe,
  listDossiers,
  startDossierRefresh,
} from '../lib/api';
import { Hosts } from './Hosts';

// One host, for the tests about the line above the table.
const LIST: DossierList = {
  rows: [
    {
      ip: '192.0.2.24',
      found: true,
      fields: [],
      first_seen: '2026-08-01T00:00:00+00:00',
      last_seen: '2026-08-13T11:00:00+00:00',
      last_built_at: '2026-08-13T11:30:00+00:00',
      last_observed_at: '2026-08-13T11:00:00+00:00',
      event_count: 12,
      identity_rebound_at: null,
      build_error: null,
      override_count: 0,
      conflict_count: 0,
      reporting: true,
    },
  ],
  total: 1,
  limit: 50,
  offset: 0,
};

// Nothing built. A sweep that never ran and a sweep that died against a down
// grid leave the same empty table, which is the whole difficulty.
const NO_HOSTS: DossierList = { rows: [], total: 0, limit: 50, offset: 0 };

const SUMMARY: DossierSummary = {
  hosts: 1,
  never_built: 0,
  named: 0,
  reporting: 1,
  conflicts: 0,
  roles: {},
  last_built_at: '2026-08-13T11:30:00+00:00',
  schedule_enabled: true,
};

const LAST_RUN = '2026-08-13T11:30:00+00:00';

/** A finished, non-running sweep whose summary is whatever the test hands in. */
const status = (last_summary: Record<string, unknown> | null): DossierRefreshStatus => ({
  running: false,
  last_run: LAST_RUN,
  last_summary,
  note: null,
});

beforeEach(() => {
  vi.mocked(listDossiers).mockReset().mockResolvedValue(LIST);
  vi.mocked(getDossierConflicts).mockReset().mockResolvedValue({ pending: 0, rows: [] });
  vi.mocked(getDossierSummary).mockReset().mockResolvedValue(SUMMARY);
  vi.mocked(getDossierRefreshStatus).mockReset();
  vi.mocked(startDossierRefresh).mockReset();
  // Most of these tests read the sweep as an admin — the FULL record, strings
  // and all. The non-admin projection has its own describe at the bottom.
  vi.mocked(getMe).mockReset().mockResolvedValue({ username: 'ana', role: 'admin', status: '' });
});

const mount = async (last_summary: Record<string, unknown> | null) => {
  vi.mocked(getDossierRefreshStatus).mockResolvedValue(status(last_summary));
  render(
    <MemoryRouter initialEntries={['/hosts']}>
      <Hosts />
    </MemoryRouter>,
  );
  // The table resolving proves the admin-gated status call has resolved too.
  await screen.findByText('192.0.2.24');
};

/** The same screen with nothing built, which is the first-run branch. */
const mountEmpty = async (
  last_summary: Record<string, unknown> | null,
  last_run: string | null = LAST_RUN,
  running = false,
) => {
  vi.mocked(listDossiers).mockResolvedValue(NO_HOSTS);
  vi.mocked(getDossierRefreshStatus).mockResolvedValue({
    running,
    last_run,
    last_summary,
    note: null,
  });
  render(
    <MemoryRouter initialEntries={['/hosts']}>
      <Hosts />
    </MemoryRouter>,
  );
  // In the empty state whatever it decides to say above it.
  await screen.findByText(/turn on scheduled sweeps/);
};

describe('Hosts sweep report — a degraded sweep vs a quiet one', () => {
  it('marks the sweep degraded when it recorded errors', async () => {
    await mount({
      hosts_built: 0,
      fields_written: 0,
      errors: [
        'census: ConnectionError querying logs-*',
        'host 192.0.2.24: ConnectionError querying logs-*',
      ],
    });
    const note = await screen.findByTestId('sweep-degraded');
    expect(note.textContent).toMatch(/Sweep degraded/);
    // The count, and the fact that the LIST is short of the truth — not merely
    // that something logged somewhere.
    expect(note.textContent).toMatch(/2 errors/);
    expect(note.textContent).toMatch(/incomplete/i);
  });

  it('marks a total failure degraded, where the summary carries no counters at all', async () => {
    // What routes_dossier.py writes when the background task died outright.
    // There is no count to print, so before the fix this screen rendered
    // nothing at all about the run that never happened.
    await mount({ errors: ['refresh failed; see server logs'] });
    const note = await screen.findByTestId('sweep-degraded');
    expect(note.textContent).toMatch(/1 error\b/);
    expect(screen.queryByTestId('sweep-run-summary')).toBeNull();
  });

  it('keeps the counts a half-blind sweep earned, above them the note', async () => {
    // Partial blindness still builds what it could reach. Erasing "300 hosts
    // built" would under-report a run that really did that work.
    await mount({
      hosts_built: 300,
      fields_written: 1200,
      errors: ['host 192.0.2.99: ConnectionError querying logs-*'],
    });
    expect(await screen.findByTestId('sweep-degraded')).toBeTruthy();
    const line = screen.getByTestId('sweep-run-summary');
    expect(line.textContent).toMatch(/300 hosts built/);
  });

  it('says nothing about degradation when the sweep was clean', async () => {
    await mount({ hosts_built: 42, fields_written: 130, errors: [] });
    expect(await screen.findByTestId('sweep-run-summary')).toBeTruthy();
    expect(screen.queryByTestId('sweep-degraded')).toBeNull();
  });

  it('says nothing about degradation when a clean sweep built nothing', async () => {
    // Zero is a legitimate answer on a settled estate: nothing changed, so
    // nothing was rebuilt. Keying the badge off a count instead of off `errors`
    // is the same false signal as the bug, pointing the other way.
    await mount({ hosts_built: 0, fields_written: 0, errors: [] });
    expect(await screen.findByTestId('sweep-run-summary')).toBeTruthy();
    expect(screen.queryByTestId('sweep-degraded')).toBeNull();
  });

  it('says nothing about degradation when a healthy sweep left advisory notes', async () => {
    // DossierSummary separates `notes` from `errors` on purpose. A truncated
    // cap or a cadence ceiling is what a HEALTHY nightly sweep reports, and a
    // badge on it would fire every night until it meant nothing.
    await mount({
      hosts_built: 500,
      fields_written: 4000,
      errors: [],
      notes: ['census truncated at the 500-host cap', 'rebuild cadence ceiling reached'],
    });
    expect(await screen.findByTestId('sweep-run-summary')).toBeTruthy();
    expect(screen.queryByTestId('sweep-degraded')).toBeNull();
  });

  it('says nothing about degradation when the server sent no summary at all', async () => {
    // An older server, or a fresh process that has not swept yet.
    await mount(null);
    expect(await screen.findByText('192.0.2.24')).toBeTruthy();
    expect(screen.queryByTestId('sweep-degraded')).toBeNull();
  });

  it('names what failed rather than only counting it', async () => {
    // The errors channel is not only the grid. This one is a local
    // misconfiguration: an operator told to wait for Security Onion waits
    // forever while every nightly sweep degrades, and the reason was sitting
    // unread in the payload the screen already had.
    await mount({
      hosts_built: 0,
      fields_written: 0,
      errors: ['no internal CIDRs configured; cannot scope the network'],
    });
    const note = await screen.findByTestId('sweep-degraded');
    expect(note.textContent).toMatch(/no internal CIDRs configured/);
  });

  it('shows the first errors and counts the rest', async () => {
    // A network-wide outage is the same error hundreds of times over. The note
    // stays a note.
    await mount({
      errors: [
        'census pass: ConnectionError querying logs-*',
        'host 192.0.2.24: ConnectionError querying logs-*',
        'host 192.0.2.25: ConnectionError querying logs-*',
        'host 192.0.2.26: ConnectionError querying logs-*',
      ],
    });
    const note = await screen.findByTestId('sweep-degraded');
    expect(note.textContent).toMatch(/census pass: ConnectionError/);
    expect(note.textContent).toMatch(/2 more/);
  });

  it('keeps the degraded verdict when a Rebuild click has something to say', async () => {
    // Clicking Rebuild into a sweep already in flight answers 'already running'
    // — and that note is never cleared, so if it can suppress the verdict it
    // suppresses it for the rest of the session, including for the very sweep
    // the operator collided with.
    await mount({
      hosts_built: 0,
      fields_written: 0,
      errors: ['census pass: ConnectionError querying logs-*'],
    });
    await screen.findByTestId('sweep-degraded');
    vi.mocked(startDossierRefresh).mockResolvedValue({
      running: true,
      last_run: LAST_RUN,
      last_summary: null,
      note: 'already running',
    });
    fireEvent.click(screen.getByRole('button', { name: /Rebuild now/ }));
    expect(await screen.findByText('already running')).toBeTruthy();
    expect(screen.getByTestId('sweep-degraded')).toBeTruthy();
  });
});

describe('Hosts first run — a sweep that died is not a sweep that never ran', () => {
  it('says the first sweep failed rather than that no sweep has run', async () => {
    // Fresh install against a down grid: the sweep ran, read nothing and built
    // nothing, so the table is empty and the screen takes its first-run branch.
    // Every word of "hasn't run yet" is false over the catch-all payload, and
    // the operator who just watched the spinner stop is the one reading it.
    await mountEmpty({ errors: ['refresh failed; see server logs'] });
    const note = await screen.findByTestId('sweep-degraded');
    expect(note.textContent).toMatch(/1 error\b/);
    expect(screen.getByTestId('hosts-empty-lead').textContent).toMatch(/could not read/i);
    expect(screen.queryByText(/sweep hasn't run yet/i)).toBeNull();
  });

  it('still says no sweep has run when none has', async () => {
    await mountEmpty(null, null);
    expect(screen.getByTestId('hosts-empty-lead').textContent).toMatch(/hasn't run yet/i);
    expect(screen.queryByTestId('sweep-degraded')).toBeNull();
  });
});

// Degraded-grid sweep, 2026-08-14 (D17). The first sweep of a fresh install was
// started, the POST answered, the button dimmed and span its spinner — and the
// sentence above it went on reading "The network sweep hasn't run yet" for as
// long as the sweep took. On a grid that answers slowly that is minutes, and the
// only thing on screen that contradicted it was a disabled button.
//
// MR !75 gave this empty state a "the sweep came back blind" branch for the
// FAILED case. Running is the third case, and it outranks both: it is the only
// one where waiting is the right thing for the operator to do.
describe('Hosts first run — a sweep in flight is not a sweep that has not run', () => {
  it('says the sweep is running rather than that none has run', async () => {
    // No errors and no completed run: a first sweep, in flight right now, which
    // is exactly the state the operator who just pressed the button is in.
    await mountEmpty(null, null, true);
    // The status is a second request, so wait for the screen to have READ it —
    // "hasn't run yet" is also what renders while it is still in flight.
    const lead = await screen.findByTestId('hosts-empty-lead');
    await waitFor(() => expect(lead.textContent).toMatch(/sweep is running now/i));
    expect(lead.textContent).not.toMatch(/hasn't run yet/i);
    expect(screen.queryByText(/hasn't run yet/i)).toBeNull();
    // The reassurance about what a sweep does survives the rewrite — it is the
    // sentence that answers "is this going to touch my network?".
    expect(lead.textContent).toMatch(/nothing new touches your network/i);
  });

  it('lets the running sweep supersede the last one’s blind verdict', async () => {
    // A retry after a blind first sweep. The old run's verdict is being
    // overwritten as the operator reads it, and the degraded note above the
    // table already hides itself while a sweep is in flight for the same reason.
    await mountEmpty({ errors: ['refresh failed; see server logs'] }, LAST_RUN, true);
    const lead = await screen.findByTestId('hosts-empty-lead');
    await waitFor(() => expect(lead.textContent).toMatch(/sweep is running now/i));
    expect(lead.textContent).not.toMatch(/came back blind/i);
    expect(screen.queryByTestId('sweep-degraded')).toBeNull();
  });

  it('keeps the action honest while the sweep it would start is running', async () => {
    await mountEmpty(null, null, true);
    const button = await screen.findByRole('button', { name: /sweeping/i });
    expect(button).toBeDisabled();
    // Not "Run the first sweep" over a sweep that is already running: the label
    // is the other half of the same false sentence.
    expect(screen.queryByRole('button', { name: /run the first sweep/i })).toBeNull();
  });

  it('offers the first sweep, undimmed, when nothing is running', async () => {
    // The control. A fresh install with no sweep in flight must still get its
    // one plain action, or this fix has traded a false sentence for a dead end.
    await mountEmpty(null, null, false);
    const button = screen.getByRole('button', { name: /run the first sweep/i });
    expect(button).not.toBeDisabled();
    expect(screen.getByTestId('hosts-empty-lead').textContent).toMatch(/hasn't run yet/i);
  });

  it('says it could not check, rather than that none has run, when the status read fails', async () => {
    // The FOURTH state, review finding on task #91: the status read itself
    // failed, the code files it under data-sweep and the 4s poll is paused —
    // so whatever sentence stands here stands for the session. "Hasn't run
    // yet" is the one claim this screen has just proven it cannot make;
    // HostDetail answers the identical failure with "could not check".
    vi.mocked(listDossiers).mockResolvedValue(NO_HOSTS);
    vi.mocked(getDossierRefreshStatus).mockRejectedValue(new Error('503 Service Unavailable'));
    render(
      <MemoryRouter initialEntries={['/hosts']}>
        <Hosts />
      </MemoryRouter>,
    );
    // Wait for the lead to have ASKED and failed — the healthy copy also
    // renders while the read is in flight, so asserting off the first paint
    // would prove nothing.
    const lead = await screen.findByTestId('hosts-empty-lead');
    await waitFor(() => expect(lead.getAttribute('data-sweep')).toBe('unreadable'));
    expect(lead.textContent).toMatch(/could not check/i);
    // Names what failed, the same as HostDetail's unreadable block does.
    expect(lead.textContent).toMatch(/503 Service Unavailable/);
    // The negative is proven live by the controls above, where this same regex
    // DOES match the healthy lead.
    expect(screen.queryByText(/hasn't run yet/i)).toBeNull();
    // The one action survives, under a label that does not claim a first.
    const button = screen.getByRole('button', { name: /^run a sweep$/i });
    expect(button).not.toBeDisabled();
    expect(screen.queryByRole('button', { name: /run the first sweep/i })).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// The NON-admin read (task #91). GET /dossiers/refresh is admin-gated because
// `last_summary` carries the sweep's raw failure strings — so until this task
// the screen never asked ANYTHING for an analyst, and its empty state read
// "The network sweep hasn't run yet" over a sweep that ran and died: the false
// all-clear, served to the role least able to check. A non-admin now reads the
// CLOSED sweep-health projection (running / degraded / last_run / error COUNT
// — never the strings), and these tests pin both halves of that decision: the
// disclosure works without the admin record, and the strings still never reach
// this reader.
//
// The projection is stubbed at the fetch boundary because the screen
// deliberately does not route it through lib/api (that file belongs to another
// branch); the shared setup's afterEach unstubs.
// ---------------------------------------------------------------------------
describe('Hosts sweep report for a NON-admin — the projection keeps the screen honest', () => {
  const stubSweepHealth = (health: {
    running: boolean;
    degraded: boolean;
    last_run: string | null;
    error_count: number;
  }) =>
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (!url.includes('/api/v1/dossiers/sweep-health')) {
          throw new Error(`Unmocked network call in test: ${init?.method ?? 'GET'} ${url}`);
        }
        return { ok: true, status: 200, json: async () => health } as Response;
      }),
    );

  const asAnalyst = () =>
    vi.mocked(getMe).mockResolvedValue({ username: 'ana', role: 'analyst', status: '' });

  const mountScreen = () =>
    render(
      <MemoryRouter initialEntries={['/hosts']}>
        <Hosts />
      </MemoryRouter>,
    );

  /** Wait until the empty lead has READ the projection and reached `facet` —
   *  the healthy copy also renders while the status request is in flight, so a
   *  control asserting it off the first paint would prove nothing. */
  const settledLead = async (facet: 'running' | 'blind' | 'read' | 'unreadable') => {
    const lead = await screen.findByTestId('hosts-empty-lead');
    await waitFor(() => expect(lead.getAttribute('data-sweep')).toBe(facet));
    return lead;
  };

  it('says the first sweep died rather than that none has run', async () => {
    asAnalyst();
    vi.mocked(listDossiers).mockResolvedValue(NO_HOSTS);
    stubSweepHealth({ running: false, degraded: true, last_run: LAST_RUN, error_count: 1 });
    mountScreen();
    const lead = await settledLead('blind');
    expect(lead.textContent).toMatch(/could not read/i);
    expect(screen.queryByText(/hasn't run yet/i)).toBeNull();
    // The verdict and the count travel; the strings do not. The negative
    // selector is proven live by the admin tests above, where the same regex
    // DOES match the rendered strings.
    const note = screen.getByTestId('sweep-degraded');
    expect(note.textContent).toMatch(/1 error\b/);
    expect(note.textContent).toMatch(/An admin can read what failed/i);
    expect(screen.queryByText(/ConnectionError/)).toBeNull();
    // The admin route was never asked — it could only have 403'd.
    expect(getDossierRefreshStatus).not.toHaveBeenCalled();
  });

  it('says a sweep is running rather than that none has run', async () => {
    asAnalyst();
    vi.mocked(listDossiers).mockResolvedValue(NO_HOSTS);
    stubSweepHealth({ running: true, degraded: false, last_run: null, error_count: 0 });
    mountScreen();
    const lead = await settledLead('running');
    expect(lead.textContent).toMatch(/sweep is running now/i);
    expect(screen.queryByText(/hasn't run yet/i)).toBeNull();
    expect(screen.queryByTestId('sweep-degraded')).toBeNull();
  });

  it('keeps the genuine first-run copy on a healthy fresh install (the control)', async () => {
    // A fresh estate whose sweep record is healthy-and-absent must keep the
    // honest "hasn't run yet" — a projection that always degraded would be the
    // same false story pointing the other way.
    asAnalyst();
    vi.mocked(listDossiers).mockResolvedValue(NO_HOSTS);
    stubSweepHealth({ running: false, degraded: false, last_run: null, error_count: 0 });
    mountScreen();
    const lead = await settledLead('read');
    expect(lead.textContent).toMatch(/hasn't run yet/i);
    // The analyst's action line survives; the admin's buttons stay hidden.
    expect(screen.getByText(/An admin starts it from this screen/i)).toBeTruthy();
    expect(screen.queryByRole('button', { name: /run the first sweep/i })).toBeNull();
    expect(screen.queryByTestId('sweep-degraded')).toBeNull();
  });

  it('says it could not check, rather than that none has run, when the projection read fails', async () => {
    // Review finding on task #91: a transient failure of the sweep-health
    // fetch at mount left the lead on the definite "hasn't run yet" while the
    // code itself filed the state as unknown — and the paused poll never
    // retried, so the false all-clear stood for the session. The same failure
    // on HostDetail reads "could not check"; this screen now says the same.
    asAnalyst();
    vi.mocked(listDossiers).mockResolvedValue(NO_HOSTS);
    vi.stubGlobal(
      'fetch',
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        if (!url.includes('/api/v1/dossiers/sweep-health')) {
          throw new Error(`Unmocked network call in test: ${init?.method ?? 'GET'} ${url}`);
        }
        throw new Error('Failed to fetch');
      }),
    );
    mountScreen();
    const lead = await settledLead('unreadable');
    expect(lead.textContent).toMatch(/could not check/i);
    // Proven live by the control above, where this regex DOES match the lead.
    expect(screen.queryByText(/hasn't run yet/i)).toBeNull();
    // Could-not-check is not blind: no degraded banner on a verdict this
    // screen never obtained. The analyst's action line survives.
    expect(screen.queryByTestId('sweep-degraded')).toBeNull();
    expect(screen.getByText(/An admin starts it from this screen/i)).toBeTruthy();
  });

  it('discloses a degraded sweep above a populated list too', async () => {
    // Not only the empty state: an incomplete LIST is incomplete for whoever
    // is reading it. The banner carries the verdict and the count for an
    // analyst; the failure strings stay on the admin read.
    asAnalyst();
    stubSweepHealth({ running: false, degraded: true, last_run: LAST_RUN, error_count: 3 });
    mountScreen();
    await screen.findByText('192.0.2.24');
    const note = await screen.findByTestId('sweep-degraded');
    expect(note.textContent).toMatch(/3 errors/);
    expect(note.textContent).toMatch(/incomplete/i);
    expect(note.textContent).toMatch(/An admin can read what failed/i);
    expect(screen.queryByText(/ConnectionError/)).toBeNull();
  });
});
