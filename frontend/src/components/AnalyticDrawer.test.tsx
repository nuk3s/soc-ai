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
import { AnalyticDrawer } from './AnalyticDrawer';

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
