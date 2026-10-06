// The drawer is where a retirement is decided, so it must show the evidence
// the decision needs: what the analytic observed, which leads it fed, what
// became of them, what it cost and what it can see. A retirement with no
// reason is an analytic that disappeared, so the reason input comes before
// the post, never after it.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAnalytic: vi.fn(),
  setAnalyticStatus: vi.fn(),
  startHuntConsole: vi.fn(),
}));

import {
  getAnalytic,
  setAnalyticStatus,
  startHuntConsole,
  type AnalyticDetail,
} from '../lib/api';
import { CHIP_LIVE, DEFINE_ANALYTIC } from '../lib/tooltips';
import { ShellProvider } from '../shell/ShellContext';
import { AnalyticDrawer, breachLine } from './AnalyticDrawer';

const HOUR = 3_600_000;
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();

const DETAIL: AnalyticDetail = {
  id: 'identity-4662-dcsync-nonmachine',
  title: 'A non-machine account reads directory replication rights',
  level: 'critical',
  evaluator: 'match',
  scope_kind: 'host',
  tier: 'shipped',
  status: 'live',
  no_benign_baseline: true,
  observations_7d: 12,
  leads_7d: 1,
  hunted_7d: 1,
  dismissed_7d: 0,
  shadow_hits_7d: 0,
  unread_shadow_hits: 0,
  description: 'The analytic reads event 4662 and the replication rights it names.',
  spec_text: 'id: identity-4662-dcsync-nonmachine\ntitle: DCSync\n',
  reason: null,
  ledger: {
    analytic_id: 'identity-4662-dcsync-nonmachine',
    since: iso(30 * 24 * HOUR),
    observations: 61,
    entities: 9,
    shadow_hits: 0,
    unread_shadow_hits: 0,
    leads: 4,
    hunted: 2,
    promoted: 1,
    dismissed: { expected_for_role: 2 },
    docs_scanned: 1_200_000,
    runtime_ms: 3100,
    sweeps: 30,
    coverage: { measured: 6, blind: 38 },
  },
  // The server answers the trail in creation order, oldest first.
  versions: [
    { from_status: null, to_status: 'shadow', who: 'analyst', at: iso(40 * HOUR), why: 'worth a week', has_receipts: false },
    { from_status: 'shadow', to_status: 'live', who: 'analyst', at: iso(2 * HOUR), why: 'two true hits', has_receipts: true },
  ],
  recent: [
    { entity: '10.1.2.3', count: 4, lead_id: 12, last: iso(3 * HOUR) },
    { entity: '10.1.2.4', count: 1, lead_id: null, last: iso(9 * HOUR) },
  ],
};

const mount = () =>
  render(
    <MemoryRouter>
      <ShellProvider>
        <AnalyticDrawer analyticId={DETAIL.id} onClose={() => {}} />
      </ShellProvider>
    </MemoryRouter>,
  );

beforeEach(() => {
  vi.mocked(getAnalytic).mockReset().mockResolvedValue(DETAIL);
  vi.mocked(setAnalyticStatus).mockReset().mockResolvedValue({ ...DETAIL, status: 'retired' });
  vi.mocked(startHuntConsole).mockReset().mockResolvedValue({ hunt_id: 'H1' });
});

describe('AnalyticDrawer', () => {
  // A drafted analytic that still names the host or the domain of its one
  // case fires on that case only. The drawer names each clause that pins it.
  it('lists the pins of a drafted analytic under "Specific to one case"', async () => {
    const pin = 'The clause on dns.query.name pins the analytic to one domain. Describe the behaviour.';
    vi.mocked(getAnalytic).mockResolvedValue({ ...DETAIL, pinned: [pin] });
    mount();
    const box = await screen.findByTestId('analytic-drawer-pins');
    expect(within(box).getByText('Specific to one case')).toBeTruthy();
    expect(within(box).getByText(pin)).toBeTruthy();
  });

  it('shows no pin list for an analytic that describes a behaviour', async () => {
    mount();
    await screen.findByText('Outcome ledger · last 30 days');
    expect(screen.queryByTestId('analytic-drawer-pins')).toBeNull();
    expect(screen.queryByText('Specific to one case')).toBeNull();
  });

  it('states the outcome ledger over the month', async () => {
    mount();
    await screen.findByText('Outcome ledger · last 30 days');
    expect(within(screen.getByTestId('ledger-observations')).getByText('61')).toBeTruthy();
    expect(within(screen.getByTestId('ledger-leads')).getByText('4')).toBeTruthy();
    expect(within(screen.getByTestId('ledger-hunted-promoted')).getByText('2 · 1')).toBeTruthy();
    expect(within(screen.getByTestId('ledger-dismissed')).getByText(/expected for role ×2/)).toBeTruthy();
    expect(within(screen.getByTestId('ledger-coverage')).getByText('6 measured · 38 blind')).toBeTruthy();
    // A lead it fed was hunted and promoted, so the answer is yes.
    expect(within(screen.getByTestId('ledger-fed-a-hunted-lead')).getByText('yes')).toBeTruthy();
  });

  // "Load-bearing?" is a metaphor. The cell asks the question it measures.
  it('asks whether the analytic fed a hunted lead, in those words', async () => {
    mount();
    const cell = await screen.findByTestId('ledger-fed-a-hunted-lead');
    expect(within(cell).getByText('Fed a hunted lead')).toBeTruthy();
  });

  it('answers not yet when it observed and fed nothing', async () => {
    vi.mocked(getAnalytic).mockResolvedValue({
      ...DETAIL,
      ledger: { ...DETAIL.ledger, hunted: 0, promoted: 0, observations: 3 },
    });
    mount();
    const cell = await screen.findByTestId('ledger-fed-a-hunted-lead');
    expect(within(cell).getByText('not yet')).toBeTruthy();
  });

  it('answers no data when it observed nothing', async () => {
    vi.mocked(getAnalytic).mockResolvedValue({
      ...DETAIL,
      ledger: { ...DETAIL.ledger, hunted: 0, promoted: 0, observations: 0 },
    });
    mount();
    const cell = await screen.findByTestId('ledger-fed-a-hunted-lead');
    expect(within(cell).getByText('no data')).toBeTruthy();
  });

  // A drawer for a thing that also has a page carries "Open page" in its
  // header. An analytic has no page, so this drawer carries none. The rule
  // stands for the next drawer.
  it('carries no Open page, because an analytic has no page', async () => {
    mount();
    await screen.findByTestId('analytic-id');
    expect(screen.queryByText(/open page/i)).toBeNull();
  });

  // Every status word states what it means, in the words the hit card uses.
  it('states the status in the words of the hit card', async () => {
    mount();
    await screen.findByTestId('analytic-id');
    expect(screen.getAllByTitle(CHIP_LIVE).length).toBeGreaterThan(0);
  });

  // The header carried the title alone. Two analytics on one subject read the
  // same, and the id is what an objective and a CLI call need.
  it('shows the analytic id under the title', async () => {
    mount();
    const id = await screen.findByTestId('analytic-id');
    expect(id.textContent).toBe(DETAIL.id);
    expect(id.className).toContain('font-mono');
  });

  it('writes the id into the objective of a hunt with this analytic', async () => {
    mount();
    fireEvent.click(await screen.findByRole('button', { name: 'Hunt with this' }));
    await waitFor(() => expect(startHuntConsole).toHaveBeenCalled());
    expect(vi.mocked(startHuntConsole).mock.calls[0][0]).toBe(
      `Run the analytic ${DETAIL.id} over the last 30 days with t_run_analytic and investigate every entity it returns.`,
    );
  });

  // `t_run_analytic` returns could_not_run for a profile or a model
  // analytic. The drawer offered the control and the hunt failed on step one.
  it.each(['profile', 'model'])('offers no hunt on a live %s analytic and says why', async (evaluator) => {
    vi.mocked(getAnalytic).mockResolvedValue({ ...DETAIL, evaluator });
    mount();
    expect(await screen.findByTestId('analytic-no-hunt')).toBeTruthy();
    expect(screen.getByTestId('analytic-no-hunt').textContent).toBe(
      'A hunt cannot run this analytic. The profile sweep runs it every hour.',
    );
    expect(screen.queryByRole('button', { name: 'Hunt with this' })).toBeNull();
    expect(screen.getByRole('button', { name: 'Retire' })).toBeTruthy();
  });

  it('offers the hunt on a live match analytic with no line', async () => {
    mount();
    expect(await screen.findByRole('button', { name: 'Hunt with this' })).toBeTruthy();
    expect(screen.queryByTestId('analytic-no-hunt')).toBeNull();
  });

  it('keeps every action button on one line', async () => {
    mount();
    const retire = await screen.findByRole('button', { name: 'Retire' });
    expect(retire.className).toContain('whitespace-nowrap');
  });

  it('lists the versions newest first, with the evidence chip', async () => {
    mount();
    const versions = await screen.findByTestId('analytic-versions');
    const rows = within(versions).getAllByRole('listitem');
    expect(rows).toHaveLength(2);
    expect(rows[0].textContent).toContain('shadow → live');
    expect(rows[0].textContent).toContain('evidence');
    expect(rows[1].textContent).toContain('new → shadow');
    expect(rows[1].textContent).not.toContain('evidence');
  });

  // The first transition on record read v2 and sat above the row that read
  // v1. The number an analyst quotes must name the same row every time.
  it('numbers the versions in creation order', async () => {
    mount();
    const versions = await screen.findByTestId('analytic-versions');
    const rows = within(versions).getAllByRole('listitem');
    expect(rows[0].textContent).toContain('v2');
    expect(rows[1].textContent).toContain('v1');
    expect(rows[1].textContent).toContain('new → shadow');
  });

  it('says evidence and never receipts on the version chip', async () => {
    mount();
    const versions = await screen.findByTestId('analytic-versions');
    expect(within(versions).getByText('evidence').getAttribute('title')).toBe(
      'The evidence this decision was taken on is stored on this row.',
    );
    expect(within(versions).queryByText('receipts')).toBeNull();
  });

  it('asks for a reason before it retires the analytic', async () => {
    mount();
    fireEvent.click(await screen.findByRole('button', { name: 'Retire' }));
    const confirm = screen.getByRole('button', { name: 'Confirm' });
    // Nothing is posted while the reason is empty.
    fireEvent.click(confirm);
    expect(setAnalyticStatus).not.toHaveBeenCalled();

    fireEvent.change(screen.getByPlaceholderText('Why it is retired'), {
      target: { value: 'every lead dismissed as expected for role' },
    });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    await waitFor(() =>
      expect(setAnalyticStatus).toHaveBeenCalledWith(
        DETAIL.id,
        'retired',
        'every lead dismissed as expected for role',
      ),
    );
  });

  it('shows the definition only when it is asked for', async () => {
    mount();
    expect(screen.queryByText(/title: DCSync/)).toBeNull();
    fireEvent.click(await screen.findByRole('button', { name: 'Show definition' }));
    expect(screen.getByText(/title: DCSync/)).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Hide definition' })).toBeTruthy();
  });
});


// An analytic scoped to user accounts linked every account to the host
// dossier. The dossier is keyed on an address and 404s a name.
// F2, F12, RH15, RO19. The drawer said "It has not run, or it found nothing"
// on a grid where no sweep had run, "0 documents · 0 ms · 0 sweeps" on a
// profile analytic that ran minutes ago, and "seen 7 times" beside
// "OBSERVATIONS 5".
describe('AnalyticDrawer run state and counts', () => {
  it('says the analytic has not run when no sweep ran it', async () => {
    vi.mocked(getAnalytic).mockResolvedValue({
      ...DETAIL,
      recent: [],
      last_run_at: null,
      runner_enabled: false,
    });
    mount();
    const line = await screen.findByTestId('analytic-nothing-observed');
    expect(line.textContent).toBe('This analytic has not run. Its sweep is off.');
    expect(line.textContent).not.toContain('or it found nothing');
    // The header status says so too.
    expect(screen.getByText('live, not running')).toBeTruthy();
  });

  it('says when an analytic that ran observed nothing', async () => {
    vi.mocked(getAnalytic).mockResolvedValue({
      ...DETAIL,
      recent: [],
      last_run_at: iso(HOUR),
      runner_enabled: true,
    });
    mount();
    const line = await screen.findByTestId('analytic-nothing-observed');
    expect(line.textContent).toBe(
      'This analytic ran 1h ago and observed nothing in the last 30 days.',
    );
    expect(screen.queryByText('live, not running')).toBeNull();
  });

  it('reads the cost of a profile analytic as profile runs', async () => {
    vi.mocked(getAnalytic).mockResolvedValue({
      ...DETAIL,
      evaluator: 'profile',
      ledger: { ...DETAIL.ledger, docs_scanned: 0, runtime_ms: 0, sweeps: 7, profile_runs: 24 },
    });
    mount();
    const cell = await screen.findByTestId('ledger-cost');
    expect(within(cell).getByText('24')).toBeTruthy();
    expect(within(cell).getByText('profile runs')).toBeTruthy();
    expect(cell.textContent).not.toContain('documents');
    expect(cell.textContent).not.toContain('sweeps');
    expect(cell.textContent).not.toContain('detector');
    expect(cell.getAttribute('title')).toContain('stored baselines');
  });

  // A learned detector reads the grid and builds its own baseline. The cell
  // read "4 profile runs" with a tooltip about stored baselines.
  it('reads the cost of a model analytic as detector runs', async () => {
    vi.mocked(getAnalytic).mockResolvedValue({
      ...DETAIL,
      evaluator: 'model',
      ledger: { ...DETAIL.ledger, docs_scanned: 0, runtime_ms: 0, sweeps: 0, profile_runs: 6 },
    });
    mount();
    const cell = await screen.findByTestId('ledger-cost');
    expect(within(cell).getByText('6')).toBeTruthy();
    expect(within(cell).getByText('detector runs')).toBeTruthy();
    expect(cell.textContent).not.toContain('profile run');
    expect(cell.textContent).not.toContain('documents');
    expect(cell.getAttribute('title')).toContain('builds its own baseline');
    expect(cell.getAttribute('title')).not.toContain('stored baselines');
  });

  it('says one detector run in the singular', async () => {
    vi.mocked(getAnalytic).mockResolvedValue({
      ...DETAIL,
      evaluator: 'model',
      ledger: { ...DETAIL.ledger, profile_runs: 1 },
    });
    mount();
    const cell = await screen.findByTestId('ledger-cost');
    expect(within(cell).getByText('detector run')).toBeTruthy();
  });

  it('counts a match analytic in the right number', async () => {
    vi.mocked(getAnalytic).mockResolvedValue({
      ...DETAIL,
      ledger: { ...DETAIL.ledger, sweeps: 1 },
    });
    mount();
    const cell = await screen.findByTestId('ledger-cost');
    expect(cell.textContent).toContain('1 sweep');
    expect(cell.textContent).not.toContain('1 sweeps');
  });

  it('counts each entity in observations, the unit of the ledger', async () => {
    mount();
    await screen.findByText('Outcome ledger · last 30 days');
    expect(screen.getByText('4 observations')).toBeTruthy();
    expect(screen.getByText('1 observation')).toBeTruthy();
    expect(screen.queryByText(/seen \d+ time/)).toBeNull();
  });
});

describe('AnalyticDrawer entity links', () => {
  it('links a user entity to its entity page', async () => {
    vi.mocked(getAnalytic).mockResolvedValue({
      ...DETAIL,
      scope_kind: 'user',
      recent: [{ entity: 'svc_sql', count: 4, lead_id: null, last: iso(HOUR) }],
    });
    mount();
    const link = await screen.findByRole('link', { name: 'svc_sql' });
    expect(link.getAttribute('href')).toBe('/entity/svc_sql');
  });

  it('keeps a host entity on the host page', async () => {
    mount();
    const link = await screen.findByRole('link', { name: '10.1.2.3' });
    expect(link.getAttribute('href')).toBe('/hosts/10.1.2.3');
  });
});


// The drawer said "prior run" and "plane" for the two numbers the tab beside
// it calls a profile run and telemetry, and it asked a question about
// contribution instead of stating what the answer means.
describe('AnalyticDrawer wording', () => {
  it('reads coverage in the words the Analytics tab uses', async () => {
    mount();
    const cell = await screen.findByTestId('ledger-coverage');
    const title = cell.getAttribute('title') ?? '';
    expect(title).toContain('The newest profile run, in entity evaluations.');
    expect(title).toContain('no telemetry on the grid that can answer.');
    expect(title).not.toContain('prior run');
    expect(title).not.toContain('plane');
  });

  it('states what a hunted lead answer means', async () => {
    mount();
    const cell = await screen.findByTestId('ledger-fed-a-hunted-lead');
    expect(cell.getAttribute('title')).toBe(
      'Yes if a lead this analytic fed was hunted or promoted. Retire an analytic that ' +
        'observes and never contributes.',
    );
  });

  // The drawer is where an analytic is judged, and it never said what an
  // analytic is. The sentence is the one the Analytics tab carries.
  it('says what an analytic is, under the title', async () => {
    mount();
    const line = await screen.findByTestId('define-analytic');
    expect(line.textContent).toContain(DEFINE_ANALYTIC);
  });
});

// The self-healing hold moves a live analytic back to shadow. The drawer must
// say that soc-ai did it, why, and on which numbers, so a hold never reads as
// a shadow week an analyst started.
describe('AnalyticDrawer, a system demotion', () => {
  const REASON =
    'The analytic wrote 42 hits in 24 hours. Its fire budget is 10 a day.';
  const HELD: AnalyticDetail = {
    ...DETAIL,
    status: 'shadow',
    reason: REASON,
    held_by_system: REASON,
    versions: [
      ...DETAIL.versions,
      {
        from_status: 'live',
        to_status: 'shadow',
        who: 'system:self-heal',
        at: iso(1 * HOUR),
        why: REASON,
        has_receipts: false,
        system: true,
        evidence: {
          breaches: [
            { rule: 'fire_budget', hits: 42, budget: 10 },
            { rule: 'precision_floor', precision: 0.1, floor: 0.3, reached: 1, decided: 10 },
          ],
        },
      },
    ],
  };

  it('states the hold and its reason under the description', async () => {
    vi.mocked(getAnalytic).mockResolvedValue(HELD);
    mount();
    const box = await screen.findByTestId('analytic-held');
    expect(box.textContent).toContain('soc-ai moved this analytic to shadow.');
    expect(box.textContent).toContain(REASON);
    expect(box.textContent).toContain('soc-ai does neither.');
    // The reason is said once, in the hold box.
    expect(screen.queryByText(`Reason on record: ${REASON}`)).toBeNull();
  });

  // N3 of the 2026-10-05 verification. The box said "retire it" over a
  // control that reads "Reject".
  it('names the two controls the analyst selects', async () => {
    vi.mocked(getAnalytic).mockResolvedValue(HELD);
    mount();
    const box = await screen.findByTestId('analytic-held');
    expect(box.textContent).toContain(
      'Then select Approve or Reject. Approve puts the analytic back to live. Reject retires it.',
    );
    expect(box.textContent).not.toContain('approve it to live or retire it');
    // Each name the box uses is a control on the drawer.
    expect(screen.getByRole('button', { name: 'Approve' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Reject' })).toBeTruthy();
    expect(box.title).toContain('Then select Approve or Reject.');
  });

  it('marks the system row in the ledger and prints its evidence', async () => {
    vi.mocked(getAnalytic).mockResolvedValue(HELD);
    mount();
    const versions = await screen.findByTestId('analytic-versions');
    const newest = versions.firstElementChild as HTMLElement;
    expect(newest.textContent).toContain('live → shadow');
    expect(within(newest).getByTestId('version-system').textContent).toBe('soc-ai');
    expect(newest.textContent).toContain(`"${REASON}"`);
    const evidence = within(newest).getByTestId('version-evidence');
    expect(evidence.textContent).toContain('42 hits in 24 h · budget 10 a day');
    expect(evidence.textContent).toContain('precision 0.10 on 10 hunted leads');
    expect(evidence.textContent).toContain('floor 0.30');
    // A system demotion carries evidence, and no approval receipts.
    expect(within(newest).queryByText('evidence')).toBeNull();
  });

  // The ship row "new to shadow" by system:catalog wore the amber chip, so a
  // ship read as a demotion. It gets a neutral chip. The self-heal row keeps
  // the amber one.
  it('marks the ship row neutral and the self-heal row amber', async () => {
    vi.mocked(getAnalytic).mockResolvedValue({
      ...HELD,
      versions: [
        {
          from_status: null,
          to_status: 'shadow',
          who: 'system:catalog',
          at: iso(50 * HOUR),
          why: 'The analytic shipped in shadow. An analyst approves it to live after the shadow week.',
          has_receipts: false,
          system: true,
        },
        { from_status: 'shadow', to_status: 'live', who: 'analyst', at: iso(30 * HOUR), why: 'ok', has_receipts: false },
        HELD.versions[HELD.versions.length - 1],
      ],
    });
    mount();
    const versions = await screen.findByTestId('analytic-versions');
    const rows = Array.from(versions.children) as HTMLElement[];
    const [heal, analyst, ship] = rows;
    // The ship row: a neutral chip, no amber.
    const shipped = within(ship).getByTestId('version-shipped');
    expect(shipped.textContent).toBe('shipped in shadow');
    expect(shipped.className).not.toContain('text-warn');
    expect(shipped.getAttribute('title')).toContain('A new shipped analytic starts in shadow.');
    expect(within(ship).queryByTestId('version-system')).toBeNull();
    // The self-heal row: the amber chip stays.
    const amber = within(heal).getByTestId('version-system');
    expect(amber.textContent).toBe('soc-ai');
    expect(amber.className).toContain('text-warn');
    expect(within(heal).queryByTestId('version-shipped')).toBeNull();
    // An analyst row wears neither.
    expect(within(analyst).queryByTestId('version-system')).toBeNull();
    expect(within(analyst).queryByTestId('version-shipped')).toBeNull();
  });

  it('marks no analyst row as a system change', async () => {
    mount();
    await screen.findByTestId('analytic-versions');
    expect(screen.queryByTestId('version-system')).toBeNull();
    expect(screen.queryByTestId('version-evidence')).toBeNull();
    expect(screen.queryByTestId('analytic-held')).toBeNull();
  });

  it('offers the analyst the approval on a held analytic', async () => {
    vi.mocked(getAnalytic).mockResolvedValue(HELD);
    mount();
    await screen.findByTestId('analytic-held');
    expect(screen.getByRole('button', { name: 'Approve' })).toBeTruthy();
    expect(screen.getByRole('button', { name: 'Reject' })).toBeTruthy();
  });
});

describe('breachLine', () => {
  it('reads the hours the budget read, after an approval inside the day', () => {
    expect(breachLine({ rule: 'fire_budget', hits: 4, budget: 3, window_hours: 3 })).toBe(
      '4 hits in 3 h · budget 3 a day',
    );
  });

  it('prints the numbers of a rule this console does not know', () => {
    expect(breachLine({ rule: 'new_rule', score: 3 })).toBe('new rule · score 3');
  });
});
