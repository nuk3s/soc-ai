// The Operate hub's hunt-catalog panel: every declarative spec, its level,
// when it last swept and last fired, whether it is blind, and its 24h counts.
//
// This is the one thing on Operate that fetches. The catalog's whole point is
// that it runs unattended, so the page an operator opens to check on
// operations has to be able to say whether it is actually running — four
// rows of zeros mean one thing with the loop on and another with it off, and
// a spec that has never been swept must read as untested, not as clean.
// Those distinctions are what the assertions below pin: catalog order kept
// (never re-sorted), "not yet swept" for a null trail, the blind marker on
// exactly the blind row, the error's text in the tooltip, and the sweeps-off
// hint that changes shape in the read-only demo.
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getHuntCatalog: vi.fn(),
  // A click on an analytic title opens the drawer, which reads the analytic.
  getAnalytic: vi.fn(),
}));

import { getAnalytic, getHuntCatalog, type HuntCatalog, type HuntCatalogSpec } from '../lib/api';
import { DemoProvider } from '../lib/demo';
import { ShellProvider } from '../shell/ShellContext';
import { Operate } from './Operate';

const HOUR = 3_600_000;
// Relative to now so `ago()` renders deterministically ("2h ago"), and
// toISOString ends in `Z` — the same shape the route emits.
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();

// Deliberately NOT alphabetical and NOT by level: a panel that quietly
// re-sorted by either would still show every title, so only a fixture that
// disagrees with both orders can tell "catalog order kept" from "sorted".
const SPECS: HuntCatalogSpec[] = [
  {
    id: 'lateral-psexec-service-install',
    title: 'Remote service installed over SMB (PsExec-style)',
    level: 'medium',
    scope_kind: 'host',
    evaluator: 'match',
    coverage: null,
    attack: ['T1569.002'],
    last_swept_at: iso(1 * HOUR),
    last_fired_at: iso(2 * HOUR),
    blind: false,
    last_error: null,
    sweeps_24h: 24,
    fired_24h: 3,
    fresh_24h: 1,
    already_handled_24h: 2,
    // Two of the window's 24 sweeps were `spec-sweep --shadow` runs.
    shadow_24h: 2,
    undecided_docs: 0,
    unattributed_docs: 0,
    truncated_docs: 0,
  },
  {
    id: 'identity-4662-dcsync-nonmachine',
    title: 'Directory replication requested by a non-machine account (DCSync)',
    level: 'critical',
    scope_kind: 'user',
    evaluator: 'match',
    coverage: null,
    attack: ['T1003.006'],
    // Two minutes, not the hour the other rows carry: a panel that rendered
    // one shared time, or the catalog's last_sweep_at, would still say
    // "1h ago" here, so only a row that disagrees can prove the value is
    // read per spec.
    last_swept_at: iso(2 * 60_000),
    last_fired_at: null,
    blind: true,
    last_error: null,
    sweeps_24h: 24,
    fired_24h: 0,
    fresh_24h: 0,
    already_handled_24h: 0,
    shadow_24h: 0,
    undecided_docs: 0,
    unattributed_docs: 0,
    truncated_docs: 0,
  },
  {
    id: 'egress-dns-long-txt',
    title: 'Abnormally long DNS TXT answers to one resolver',
    level: 'low',
    scope_kind: 'host',
    evaluator: 'match',
    coverage: null,
    attack: ['T1071.004'],
    last_swept_at: iso(1 * HOUR),
    last_fired_at: null,
    blind: false,
    last_error: 'ConnectionError: grid down',
    sweeps_24h: 24,
    fired_24h: 0,
    fresh_24h: 0,
    already_handled_24h: 0,
    shadow_24h: 0,
    undecided_docs: 0,
    unattributed_docs: 0,
    truncated_docs: 0,
  },
  {
    id: 'never-swept-spec',
    title: 'A spec the loop has never reached',
    level: 'informational',
    scope_kind: 'host',
    evaluator: 'match',
    coverage: null,
    attack: [],
    last_swept_at: null,
    last_fired_at: null,
    blind: false,
    last_error: null,
    sweeps_24h: 0,
    fired_24h: 0,
    fresh_24h: 0,
    already_handled_24h: 0,
    shadow_24h: 0,
    undecided_docs: 0,
    unattributed_docs: 0,
    truncated_docs: 0,
  },
  {
    // The live symptom, measured on a range: every counter zero, swept two
    // minutes ago, not blind, no error — and the last sweep threw away 5,240
    // documents its exclusions could not be evaluated against. Byte for byte
    // the row a healthy quiet spec renders, which is what the marker fixes.
    id: 'identity-4624-machine-accounts',
    title: 'Interactive logon by a non-machine account',
    level: 'medium',
    scope_kind: 'user',
    evaluator: 'match',
    coverage: null,
    attack: ['T1078'],
    last_swept_at: iso(2 * 60_000),
    last_fired_at: null,
    blind: false,
    last_error: null,
    sweeps_24h: 24,
    fired_24h: 0,
    fresh_24h: 0,
    already_handled_24h: 0,
    shadow_24h: 0,
    undecided_docs: 5240,
    unattributed_docs: 0,
    truncated_docs: 0,
  },
  {
    // Undecided's sibling: these documents MATCHED and grouped into no scope,
    // so they sit inside the sweep's matched count — which never reaches this
    // panel — and inside no candidate. Every counter the row does carry comes
    // from the candidate list, so this renders as another byte-for-byte copy
    // of a healthy quiet spec over twelve real hits.
    id: 'egress-http-beacon-no-host',
    title: 'Regular outbound HTTP with no Host header',
    level: 'high',
    scope_kind: 'ip',
    evaluator: 'match',
    coverage: null,
    attack: ['T1071.001'],
    last_swept_at: iso(2 * 60_000),
    last_fired_at: null,
    blind: false,
    last_error: null,
    sweeps_24h: 24,
    fired_24h: 0,
    fresh_24h: 0,
    already_handled_24h: 0,
    shadow_24h: 0,
    undecided_docs: 0,
    unattributed_docs: 12,
    truncated_docs: 0,
  },
  {
    // The one unclean row that does NOT read as zeros, which is why it needs
    // its own fixture rather than a third value on the row above: the grid cut
    // the grouping at the bucket ceiling, so "fired 4 · fresh 9" is a true
    // count of what came back and a false count of what is there. An
    // under-report is indistinguishable from a total without the chip.
    id: 'identity-4625-password-spray',
    title: 'Failed logons across many accounts from one source',
    level: 'high',
    scope_kind: 'user',
    evaluator: 'match',
    coverage: null,
    attack: ['T1110.003'],
    last_swept_at: iso(2 * 60_000),
    last_fired_at: iso(3 * 60_000),
    blind: false,
    last_error: null,
    sweeps_24h: 24,
    fired_24h: 4,
    fresh_24h: 9,
    already_handled_24h: 1,
    shadow_24h: 0,
    undecided_docs: 0,
    unattributed_docs: 0,
    truncated_docs: 460,
  },
];

const ON: HuntCatalog = {
  specs: SPECS,
  sweeps_enabled: true,
  sweep_interval_minutes: 60,
  sweep_window_minutes: 1440,
  last_sweep_at: iso(1 * HOUR),
};

const OFF: HuntCatalog = {
  ...ON,
  sweeps_enabled: false,
  last_sweep_at: null,
};

// ShellProvider because the analytic drawer registers with the modal stack.
// `main.tsx` wraps the whole app in it, so this mirrors the real tree.
const mount = (demo = false) =>
  render(
    <DemoProvider demo={demo}>
      <MemoryRouter>
        <ShellProvider>
          <Operate />
        </ShellProvider>
      </MemoryRouter>
    </DemoProvider>,
  );

beforeEach(() => {
  vi.mocked(getHuntCatalog).mockReset().mockResolvedValue(ON);
});

describe('Operate hunt-catalog panel', () => {
  it('reads the catalog exactly once on mount', async () => {
    mount();
    await waitFor(() => expect(getHuntCatalog).toHaveBeenCalledTimes(1));
    // Renamed in 1.5.1: one analytic is one detection logic, and the word
    // "spec" left every screen with it.
    expect(await screen.findByText('Analytics')).toBeInTheDocument();
  });

  it('renders every spec title, in catalog order, never re-sorted', async () => {
    mount();
    await screen.findByText(SPECS[0].title);
    const rows = screen.getAllByRole('listitem');
    expect(rows).toHaveLength(SPECS.length);
    rows.forEach((row, i) => expect(row).toHaveTextContent(SPECS[i].title));
  });

  it('shows the level pill and the 24h counts on a swept row, and "last fired" as a relative time', async () => {
    mount();
    await screen.findByText(SPECS[0].title);
    const row = screen.getAllByRole('listitem')[0];
    expect(within(row).getByText('Medium')).toBeInTheDocument();
    expect(within(row).getByText(/fired 3 · fresh 1 · handled 2/)).toBeInTheDocument();
    expect(within(row).getByText(/last fired 2h ago/i)).toBeInTheDocument();
  });

  // last_swept_at arrives per spec and 1.5.1 read it only as a never/ever
  // boolean, so the CRITICAL DCSync row read "last fired never" whether it was
  // checked ninety seconds ago or last week. That row is the point of the
  // panel: a real DCSync chain produced no alert, so "was anyone looking, and
  // when" is the question the row has to answer.
  it('shows when each spec was last swept, from its own trail row', async () => {
    mount();
    await screen.findByText(SPECS[0].title);
    const rows = screen.getAllByRole('listitem');
    expect(within(rows[0]).getByText(/last swept 1h ago/i)).toBeInTheDocument();
    expect(within(rows[1]).getByText(/last swept 2m ago/i)).toBeInTheDocument();
    // The never-swept row says "not yet swept" and nothing about a time.
    expect(within(rows[3]).queryByText(/last swept/i)).toBeNull();
  });

  // The counters rendered bare, and "these are the last 24h" lived in a title
  // tooltip on every row, which nobody hovers. The window is one fact about
  // the whole list, so it is said once, above the rows, not once per row.
  it('says the counts are the last 24h once, above the list, not per row', async () => {
    mount();
    await screen.findByText(SPECS[0].title);
    const legend = screen.getAllByText(/last 24 h/i);
    expect(legend).toHaveLength(1);
    expect(legend[0].closest('li')).toBeNull();
    // The definitions ride on the legend's tooltip: one hover, not four.
    expect(legend[0].closest('[title]')?.getAttribute('title')).toMatch(/fresh: a match no observation had covered/i);
  });

  it('an empty catalog has no counts legend to explain', async () => {
    vi.mocked(getHuntCatalog).mockResolvedValue({ ...ON, specs: [] });
    mount();
    await screen.findByText(/no analytics are installed/i);
    expect(screen.queryByText(/last 24h/i)).toBeNull();
  });

  it('says "last fired never" for a swept spec that has not fired, not a blank', async () => {
    mount();
    await screen.findByText(SPECS[1].title);
    const row = screen.getAllByRole('listitem')[1];
    expect(within(row).getByText(/last fired never/i)).toBeInTheDocument();
  });

  it('marks a never-swept spec "not yet swept" instead of fabricating zero counts', async () => {
    mount();
    await screen.findByText(SPECS[3].title);
    const rows = screen.getAllByRole('listitem');
    expect(within(rows[3]).getByText(/not yet swept/i)).toBeInTheDocument();
    expect(within(rows[3]).queryByText(/fired 0/)).toBeNull();
    expect(within(rows[3]).queryByText(/last fired/i)).toBeNull();
    // Only that row — a swept spec with zeros still shows its zeros.
    expect(screen.getAllByText(/not yet swept/i)).toHaveLength(1);
    expect(within(rows[1]).getByText(/fired 0 · fresh 0 · handled 0/)).toBeInTheDocument();
  });

  it('shows the blind marker on the blind row only, with the telemetry-absent tooltip', async () => {
    mount();
    await screen.findByText(SPECS[1].title);
    const rows = screen.getAllByRole('listitem');
    const blind = within(rows[1]).getByTitle(/precondition matched nothing on the last sweep/i);
    expect(blind).toHaveTextContent(/blind/i);
    expect(blind.getAttribute('title')).toMatch(/is absent\. This is not a clean result/i);
    expect(within(rows[0]).queryByTitle(/precondition matched nothing/i)).toBeNull();
    expect(within(rows[2]).queryByTitle(/precondition matched nothing/i)).toBeNull();
    expect(within(rows[3]).queryByTitle(/precondition matched nothing/i)).toBeNull();
  });

  // A spec whose exclusions read a field the grid does not always carry
  // discards every document missing it. The sweep counts them, calls the run
  // not clean and says so on the command line and in the notification; this
  // panel, whose whole job is that a spec gone dark "would otherwise read as
  // clean", could not read the number at all.
  it('marks a row that discarded documents, on that row only, with the not-clean tooltip', async () => {
    mount();
    await screen.findByText(SPECS[4].title);
    const rows = screen.getAllByRole('listitem');
    const marker = within(rows[4]).getByText(/5240 undecided/);
    expect(marker).toHaveStyle({ color: '#f5a623' });
    const title = marker.closest('[title]')?.getAttribute('title') ?? '';
    expect(title).toMatch(/neither matched nor ruled out/i);
    expect(title).toMatch(/not a clean result/i);
    // The negative control: four rows that discarded nothing, one of them
    // blind and one errored, wear no marker.
    for (const row of rows.slice(0, 4)) expect(within(row).queryByText(/undecided/i)).toBeNull();
    // And the two rows below, which are unclean for the OTHER two reasons:
    // one chip per failure, so "undecided" must not spread to them.
    for (const row of rows.slice(5)) expect(within(row).queryByText(/undecided/i)).toBeNull();
  });

  // Same blind spot, second column. A spec that matched twelve documents and
  // grouped none of them renders "fired 0 · fresh 0 · handled 0 · last swept
  // 2m ago" — the row of a healthy quiet spec, over hits the detection made.
  it('marks a row whose matches reached no scope, on that row only', async () => {
    mount();
    await screen.findByText(SPECS[5].title);
    const rows = screen.getAllByRole('listitem');
    // The zeros this marker exists to contradict, on the same row.
    expect(within(rows[5]).getByText(/fired 0 · fresh 0 · handled 0/)).toBeInTheDocument();
    const marker = within(rows[5]).getByText(/12 unattributed/);
    expect(marker).toHaveStyle({ color: '#f5a623' });
    const title = marker.closest('[title]')?.getAttribute('title') ?? '';
    expect(title).toMatch(/could not group into any scope/i);
    expect(title).toMatch(/reached no hunt/i);
    // Every other row, including the two unclean for different reasons.
    for (const row of [...rows.slice(0, 5), ...rows.slice(6)]) {
      expect(within(row).queryByText(/unattributed/i)).toBeNull();
    }
  });

  // Same blind spot, third column, and the only one where the row does not
  // read as zeros: the counts are real and too small. "fired 4 · fresh 9" over
  // a grouping the grid cut at its ceiling is an under-report that reads
  // exactly like a total, which is the harder of the two to notice.
  it('marks a row whose grouping hit the ceiling, and says the counts are a floor', async () => {
    mount();
    await screen.findByText(SPECS[6].title);
    const rows = screen.getAllByRole('listitem');
    expect(within(rows[6]).getByText(/fired 4 · fresh 9 · handled 1/)).toBeInTheDocument();
    const marker = within(rows[6]).getByText(/460 truncated/);
    expect(marker).toHaveStyle({ color: '#f5a623' });
    const title = marker.closest('[title]')?.getAttribute('title') ?? '';
    expect(title).toMatch(/bucket ceiling/i);
    expect(title).toMatch(/a floor and not a total/i);
    for (const row of rows.slice(0, 6)) {
      expect(within(row).queryByText(/truncated/i)).toBeNull();
    }
  });

  // A new install follows the hint, runs `spec-sweep --shadow`, and reads
  // "fired 0 · fresh 2" on a spec that is working exactly as designed: a
  // shadow sweep counts what it would have surfaced toward fresh and never
  // toward fired. Without a marker that row reads as a spec that finds
  // things and refuses to report them.
  it('marks a row whose window held shadow sweeps, and says they count toward fresh, not fired', async () => {
    mount();
    await screen.findByText(SPECS[0].title);
    const rows = screen.getAllByRole('listitem');
    const marker = within(rows[0]).getByText(/shadow ×2/);
    expect(marker).toHaveStyle({ color: '#f5a623' });
    const title = marker.closest('[title]')?.getAttribute('title') ?? '';
    expect(title).toMatch(/toward fresh/i);
    expect(title).toMatch(/never toward fired/i);
    // The marker is a fact about the window, not a decoration on every row:
    // the three rows with no shadow sweeps do not wear it.
    for (const row of rows.slice(1)) expect(within(row).queryByText(/shadow/i)).toBeNull();
  });

  it('shows the error marker with the error text in its tooltip, on that row only', async () => {
    mount();
    await screen.findByText(SPECS[2].title);
    const rows = screen.getAllByRole('listitem');
    const err = within(rows[2]).getByTitle('ConnectionError: grid down');
    expect(err).toHaveTextContent(/error/i);
    expect(within(rows[0]).queryByText(/^error$/i)).toBeNull();
    expect(within(rows[1]).queryByText(/^error$/i)).toBeNull();
  });

  it('sweeps on: the status line names the cadence, the window and the last sweep', async () => {
    mount();
    // The bare green tag, no qualifier: ON's newest trail row is one interval
    // old, which is a loop that is landing on schedule.
    const tag = await screen.findByText(/^sweeps on$/i);
    expect(tag).toHaveStyle({ color: '#3fb950' });
    expect(screen.getByText(/every 60m/)).toBeInTheDocument();
    expect(screen.getByText(/looks back 24h/)).toBeInTheDocument();
    expect(screen.getByText(/last sweep 1h ago/i)).toBeInTheDocument();
    expect(screen.queryByText(/spec-sweep --shadow/)).toBeNull();
    // "once enabled" is the off branch's qualifier; on, the cadence is live.
    expect(screen.queryByText(/once enabled/)).toBeNull();
  });

  // `sweeps_enabled` is the config flag. Liveness is whether a sweep has
  // actually landed lately: the scheduler swallows a failing sweep and the
  // flag stays true, so a loop that died two days ago must not render green.
  it('sweeps on, newest trail row days old: amber "overdue", never the plain green tag', async () => {
    vi.mocked(getHuntCatalog).mockResolvedValue({ ...ON, last_sweep_at: iso(3 * 24 * HOUR) });
    mount();
    const tag = await screen.findByText(/^sweeps on, overdue$/i);
    expect(tag).toHaveStyle({ color: '#f5a623' });
    expect(screen.queryByText(/^sweeps on$/i)).toBeNull();
    // The cadence and the stale timestamp stay on the line: they are how the
    // operator sizes the gap.
    expect(screen.getByText(/every 60m/)).toBeInTheDocument();
    expect(screen.getByText(/last sweep 3d ago/i)).toBeInTheDocument();
  });

  it('sweeps on, no trail at all: says "no sweep recorded yet" in amber, not green', async () => {
    vi.mocked(getHuntCatalog).mockResolvedValue({ ...ON, last_sweep_at: null });
    mount();
    const tag = await screen.findByText(/^sweeps on, no sweep recorded yet$/i);
    expect(tag).toHaveStyle({ color: '#f5a623' });
    expect(screen.queryByText(/^sweeps on$/i)).toBeNull();
    // The tag already says it; a trailing "last sweep never" would say it twice.
    expect(screen.queryByText(/last sweep never/i)).toBeNull();
  });

  it('sweeps off: says how to turn them on, pointing at the config section', async () => {
    vi.mocked(getHuntCatalog).mockResolvedValue(OFF);
    mount();
    expect(await screen.findByText(/sweeps off/i)).toBeInTheDocument();
    expect(screen.getByText(/soc-ai spec-sweep --shadow/)).toBeInTheDocument();
    const link = screen.getByRole('link', { name: /triage automation/i });
    expect(link).toHaveAttribute('href', '/config#triage-automation');
    expect(screen.queryByText(/operator turns sweeps on/i)).toBeNull();
    // A null trail with the flag off is a fresh install: the line says the
    // command in the hint has never been run, so running it visibly changes
    // the line.
    expect(screen.getByText(/last sweep never/i)).toBeInTheDocument();
  });

  // The state that shipped broken in 1.5.1: the flag off, but an operator
  // running sweeps by hand from the CLI, which is what the hint tells them to
  // do. The trail and the settings are true either way, and dropping them made
  // the panel say "off" over a row that had fired nine minutes earlier.
  it('sweeps off, but a sweep has landed: the cadence, the window and the last sweep still render', async () => {
    vi.mocked(getHuntCatalog).mockResolvedValue({ ...OFF, last_sweep_at: iso(1 * HOUR) });
    mount();
    expect(await screen.findByText(/sweeps off/i)).toBeInTheDocument();
    expect(screen.getByText(/looks back 24h/)).toBeInTheDocument();
    expect(screen.getByText(/last sweep 1h ago/i)).toBeInTheDocument();
    // The interval is a schedule that is not running, so the line says so
    // rather than claiming a cadence.
    expect(screen.getByText(/every 60m once enabled/)).toBeInTheDocument();
    // The call to action stays: the facts do not replace it.
    expect(screen.getByText(/soc-ai spec-sweep --shadow/)).toBeInTheDocument();
    expect(screen.getByRole('link', { name: /triage automation/i })).toHaveAttribute(
      'href',
      '/config#triage-automation',
    );
  });

  it('sweeps off in the demo: the facts render there too, with the demo hint', async () => {
    vi.mocked(getHuntCatalog).mockResolvedValue({ ...OFF, last_sweep_at: iso(1 * HOUR) });
    mount(true);
    expect(await screen.findByText(/sweeps off/i)).toBeInTheDocument();
    expect(screen.getByText(/every 60m once enabled/)).toBeInTheDocument();
    expect(screen.getByText(/last sweep 1h ago/i)).toBeInTheDocument();
    expect(screen.getByText(/operator turns sweeps on/i)).toBeInTheDocument();
  });

  it('sweeps off in the read-only demo: the hint says the operator enables it, not "go to Config"', async () => {
    vi.mocked(getHuntCatalog).mockResolvedValue(OFF);
    mount(true);
    expect(await screen.findByText(/sweeps off/i)).toBeInTheDocument();
    expect(screen.getByText(/operator turns sweeps on/i)).toBeInTheDocument();
    expect(screen.queryByText(/spec-sweep --shadow/)).toBeNull();
    expect(screen.queryByRole('link', { name: /triage automation/i })).toBeNull();
  });

  it('links to the analytic hits', async () => {
    mount();
    const link = await screen.findByRole('link', { name: /open analytic hits/i });
    expect(link).toHaveAttribute('href', '/hunts');
  });

  it('names a failed read instead of sitting on "Reading…" forever', async () => {
    vi.mocked(getHuntCatalog).mockRejectedValue(new Error('500'));
    mount();
    expect(await screen.findByText(/couldn't read the hunt catalog/i)).toBeInTheDocument();
    expect(screen.queryByText(/reading the hunt catalog/i)).toBeNull();
    expect(screen.queryByRole('listitem')).toBeNull();
  });

  it('an empty catalog says so rather than rendering a bare header', async () => {
    vi.mocked(getHuntCatalog).mockResolvedValue({ ...ON, specs: [] });
    mount();
    expect(await screen.findByText(/no analytics are installed/i)).toBeInTheDocument();
  });
});

// Fake timers scoped to this describe only (Dashboard.setupHealth.test.tsx
// precedent): the tests above need no poll tick, this one is ABOUT one.
// Advance under `act`, then assert synchronously.
describe('Operate hunt-catalog panel — poll cadence', () => {
  beforeEach(() => vi.useFakeTimers());
  afterEach(() => vi.useRealTimers());

  it('re-reads the catalog on the 5-minute tick, and not before', async () => {
    mount();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(getHuntCatalog).toHaveBeenCalledTimes(1);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(299_000);
    });
    expect(getHuntCatalog).toHaveBeenCalledTimes(1);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1_000);
    });
    expect(getHuntCatalog).toHaveBeenCalledTimes(2);
  });

  // The notice's own Refresh button is the only foreground refetch this panel
  // has. useAsync keeps the data and the fail count through a foreground
  // failure and sets `error`, which the panel never read once data was on
  // screen: the operator clicked, the read failed, and nothing changed.
  it('a failed manual refresh from the stale notice says so instead of showing the same notice again', async () => {
    mount();
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(screen.getByText(SPECS[0].title)).toBeInTheDocument();
    vi.mocked(getHuntCatalog).mockRejectedValue(new Error('500'));
    // Two failed polls earn the background stale notice and its button.
    await act(async () => {
      await vi.advanceTimersByTimeAsync(300_000);
    });
    await act(async () => {
      await vi.advanceTimersByTimeAsync(300_000);
    });
    const notice = screen.getByRole('status');
    expect(notice).toHaveTextContent(/this data is from/i);
    expect(notice).not.toHaveTextContent(/refresh failed/i);
    fireEvent.click(screen.getByRole('button', { name: /refresh/i }));
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(screen.getByRole('status')).toHaveTextContent(/refresh failed/i);
    // The poll goes on underneath, so the notice still promises the retry,
    // and the last-good rows stay on screen.
    expect(screen.getByRole('status')).toHaveTextContent(/retries automatically/i);
    expect(screen.getByText(SPECS[0].title)).toBeInTheDocument();
  });
});

// ---------------------------------------------------------------------------
// Profile specs are a different loop
//
// A `profile` spec is answered from an entity's stored behavioural baseline by
// `soc-ai priors`, not by the catalog sweep. Rendered with the sweep's own
// columns, nine of them showed "fired 0 · fresh 0 · handled 0" and a 23-hour
// -old error chip under a green "Sweeps on" — nine specs reading as quiet when
// the truth was that this loop had stopped touching them entirely.
// ---------------------------------------------------------------------------

const PRIOR: HuntCatalogSpec = {
  id: 'prior-hypervisor-novel-served-port',
  title: 'A hypervisor served a port it has never served before',
  level: 'high',
  scope_kind: 'host',
  evaluator: 'profile',
  coverage: {
    last_run_at: iso(1 * HOUR),
    measured: 0,
    learning: 3,
    blind: 251,
    not_applicable: 6,
    fired: 0,
    shadow: true,
  },
  attack: ['T1133'],
  // Deliberately populated: these are the STALE fields from before the split,
  // and the row must not render any of them.
  last_swept_at: iso(23 * HOUR),
  last_fired_at: null,
  blind: false,
  last_error: "AttributeError: 'NoneType' object has no attribute 'exclusion_fields'",
  sweeps_24h: 7,
  fired_24h: 0,
  fresh_24h: 0,
  already_handled_24h: 0,
  shadow_24h: 0,
  undecided_docs: 0,
  unattributed_docs: 0,
  truncated_docs: 0,
};

describe('Operate hunt-catalog panel — profile specs', () => {
  beforeEach(() => {
    vi.mocked(getHuntCatalog)
      .mockReset()
      .mockResolvedValue({ ...ON, specs: [...SPECS, PRIOR] });
  });

  it('groups them apart from the specs this loop sweeps', async () => {
    mount();
    expect(await screen.findByText(/Evaluated against behavioural profiles/)).toBeTruthy();
    expect(screen.getByText(/Evaluated against behavioural profiles · 1/)).toBeTruthy();
  });

  it('shows the prior sweep’s coverage instead of this loop’s counters', async () => {
    // The shadow log printed "blind=251 · could not be scored against any
    // entity" in one line while this row showed zeros. Now the row says it.
    mount();
    const row = (await screen.findByText(PRIOR.title)).closest('li')!;
    expect(within(row).getByText(/measured 0/)).toBeTruthy();
    expect(within(row).getByText(/blind 251/)).toBeTruthy();
    expect(within(row).getByText(/last run 1h ago/)).toBeTruthy();
    // An unscored spec is marked, in amber, rather than reading as quiet.
    expect(within(row).getByText('unscored')).toBeTruthy();
    // None of the catalog sweep's vocabulary may appear on this row.
    expect(within(row).queryByText(/last swept/)).toBeNull();
    expect(within(row).queryByText(/not yet swept/)).toBeNull();
  });

  it('says a never-run profile spec has not been run, not that it is clean', async () => {
    vi.mocked(getHuntCatalog)
      .mockReset()
      .mockResolvedValue({ ...ON, specs: [...SPECS, { ...PRIOR, coverage: null }] });
    mount();
    const row = (await screen.findByText(PRIOR.title)).closest('li')!;
    expect(within(row).getByText(/not yet run/)).toBeTruthy();
    expect(within(row).queryByText('unscored')).toBeNull();
  });

  it('does not mark a scored spec as unscored', async () => {
    vi.mocked(getHuntCatalog)
      .mockReset()
      .mockResolvedValue({
        ...ON,
        specs: [...SPECS, { ...PRIOR, coverage: { ...PRIOR.coverage!, measured: 4, fired: 1 } }],
      });
    mount();
    const row = (await screen.findByText(PRIOR.title)).closest('li')!;
    expect(within(row).getByText(/fired 1 · measured 4/)).toBeTruthy();
    expect(within(row).queryByText('unscored')).toBeNull();
  });

  it('does not render a stale error from a loop that no longer runs it', async () => {
    // The chip was a 23-hour-old tombstone for a bug already fixed, and
    // because this loop never sweeps these specs again, nothing could ever
    // overwrite it. A permanent error badge trains operators to ignore
    // error badges.
    mount();
    const row = (await screen.findByText(PRIOR.title)).closest('li')!;
    expect(within(row).queryByText('error')).toBeNull();
  });

  it('still shows the swept specs with their own trail', async () => {
    mount();
    // The split must not swallow the specs this loop DOES sweep.
    for (const spec of SPECS) {
      expect(await screen.findByText(spec.title)).toBeTruthy();
    }
  });
});

// Operate listed an analytic and offered no way to read it. An operator had to
// change screens to answer "what does this one look for". The title opens the
// same drawer the Analytics tab opens.
describe('Operate analytic drawer', () => {
  const DETAIL = {
    id: 'lateral-psexec-service-install',
    title: 'Remote service installed over SMB (PsExec-style)',
    level: 'medium',
    evaluator: 'match',
    scope_kind: 'host',
    tier: 'shipped',
    status: 'live',
    no_benign_baseline: false,
    observations_7d: 0,
    leads_7d: 0,
    hunted_7d: 0,
    dismissed_7d: 0,
    shadow_hits_7d: 0,
    unread_shadow_hits: 0,
    description: 'A remote service was installed over SMB.',
    spec_text: 'id: lateral-psexec-service-install',
    reason: null,
    ledger: {
      analytic_id: 'lateral-psexec-service-install',
      since: iso(30 * 24 * HOUR),
      observations: 0,
      entities: 0,
      shadow_hits: 0,
      unread_shadow_hits: 0,
      leads: 0,
      hunted: 0,
      promoted: 0,
      dismissed: {},
      docs_scanned: 0,
      runtime_ms: 0,
      sweeps: 0,
      coverage: {},
    },
    versions: [],
    recent: [],
  };

  beforeEach(() => {
    vi.mocked(getAnalytic).mockReset().mockResolvedValue(DETAIL as never);
  });

  it('opens the analytic drawer from a click on the title', async () => {
    mount();
    fireEvent.click(await screen.findByRole('button', { name: SPECS[0].title }));
    await waitFor(() =>
      expect(getAnalytic).toHaveBeenCalledWith('lateral-psexec-service-install'),
    );
    expect(await screen.findByText('A remote service was installed over SMB.')).toBeTruthy();
  });

  it('opens the drawer from a profile analytic too', async () => {
    vi.mocked(getHuntCatalog).mockReset().mockResolvedValue({ ...ON, specs: [...SPECS, PRIOR] });
    vi.mocked(getAnalytic).mockResolvedValue({
      ...DETAIL,
      id: PRIOR.id,
      title: PRIOR.title,
    } as never);
    mount();
    fireEvent.click(await screen.findByRole('button', { name: PRIOR.title }));
    await waitFor(() => expect(getAnalytic).toHaveBeenCalledWith(PRIOR.id));
  });
});

// "Remove the word spec from all screens" is the 2026-09-17 design decision.
// The word names a file on disk. An analyst reading the catalog met a noun the
// rest of the product does not use.
describe('Operate analytics vocabulary', () => {
  const analyticTitles = new Set([...SPECS, PRIOR].map((s) => s.title));

  it('has no tooltip that says spec', async () => {
    vi.mocked(getHuntCatalog).mockReset().mockResolvedValue({ ...ON, specs: [...SPECS, PRIOR] });
    const { container } = mount();
    await screen.findByText(SPECS[0].title);
    const titles = Array.from(container.querySelectorAll('[title]'))
      .map((el) => el.getAttribute('title') ?? '')
      // An analytic's own title is data, not a word this app chose.
      .filter((v) => !analyticTitles.has(v));
    expect(titles.length).toBeGreaterThan(4);
    for (const v of titles) expect(v.toLowerCase()).not.toContain('spec');
  });

  it('defines the three words on a profile row, n/a included', async () => {
    vi.mocked(getHuntCatalog).mockReset().mockResolvedValue({ ...ON, specs: [...SPECS, PRIOR] });
    mount();
    const legend = await screen.findByTestId('profile-legend');
    expect(legend.textContent).toContain(
      'unscored: the host has under 7 days of history, or no telemetry the analytic can read.',
    );
    expect(legend.textContent).toContain(
      'n/a: the host’s role is outside the analytic’s scope.',
    );
  });

  it('defines fired, fresh and handled around observations', async () => {
    mount();
    await screen.findByText(SPECS[0].title);
    const legend = screen.getByText(/fired, fresh and handled cover the last 24 h/);
    const title = legend.getAttribute('title') ?? '';
    expect(title).toContain('fired: a live sweep matched and wrote an observation.');
    expect(title).toContain('fresh: a match no observation had covered.');
    expect(title).toContain('handled: a match an earlier observation already covered.');
  });

  it('says no analytics are installed on an empty catalog', async () => {
    vi.mocked(getHuntCatalog).mockReset().mockResolvedValue({ ...ON, specs: [] });
    mount();
    expect(await screen.findByText('No analytics are installed.')).toBeTruthy();
  });
});

