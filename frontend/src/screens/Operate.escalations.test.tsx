// The Operate hub's escalation-ledger panel: escalates that claimed an alert
// and never learned whether Security Onion opened a case.
//
// soc-ai claims before it opens, because the unique index on alert_id is what
// makes a repeated press safe. A claim that never gets its answer stays open
// forever and refuses every future escalate of that alert — reconciliation
// only happens on a later group press covering the same alert, so a claim
// whose alert has left the queue is permanent. Before this panel the table
// could not even be enumerated: every reader in the store takes a list of
// alert ids the caller already has.
//
// What the assertions below pin is the distinction the panel exists for. An
// empty list must read as "every escalate has an answer" and NOT as a failed
// read; a failed read must read as "could not tell" and NOT as an empty list;
// and the count must be the ledger's, not the list's, because a capped list
// reporting its own length is the same silent under-report all over again.
import { render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getHuntCatalog: vi.fn(),
  getStrandedEscalations: vi.fn(),
  getAnalyticHits: vi.fn().mockResolvedValue({ hits: [], counts: { all: 0, unread: 0, live: 0, shadow: 0 } }),
}));

// The dependency block and the job list have their own suites. Here they would
// add list items and reads that are not this suite's business.
vi.mock('../components/StatusDependenciesPanel', () => ({ StatusDependenciesPanel: () => null }));
vi.mock('../components/StatusJobsPanel', () => ({ StatusJobsPanel: () => null }));

import { getHuntCatalog, getStrandedEscalations, type StrandedClaims } from '../lib/api';
import { Operate } from './Operate';

const HOUR = 3_600_000;
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();

const SETTLED: StrandedClaims = { claims: [], total: 0, settling_minutes: 15 };

const STUCK: StrandedClaims = {
  claims: [
    {
      // Oldest first, as the store returns them: the alert that has been
      // unescalatable longest is the one to look at, and a newest-first list
      // would push it off the bottom of the cap.
      alert_id: 'ev-ancient',
      escalated_by: 'analyst',
      claimed_at: iso(96 * HOUR),
    },
    {
      alert_id: 'ev-recent',
      escalated_by: 'token:autotriage',
      claimed_at: iso(2 * HOUR),
    },
  ],
  total: 2,
  settling_minutes: 15,
};

const mount = () =>
  render(
    <MemoryRouter>
      <Operate />
    </MemoryRouter>,
  );

beforeEach(() => {
  vi.mocked(getHuntCatalog).mockReset().mockResolvedValue({
    specs: [],
    sweeps_enabled: false,
    sweep_interval_minutes: 60,
    sweep_window_minutes: 1440,
    last_sweep_at: null,
  });
  vi.mocked(getStrandedEscalations).mockReset().mockResolvedValue(SETTLED);
});

describe('Operate escalation-ledger panel', () => {
  it('reads the ledger exactly once on mount', async () => {
    mount();
    await waitFor(() => expect(getStrandedEscalations).toHaveBeenCalledTimes(1));
    expect(await screen.findByText('Escalations awaiting an answer')).toBeInTheDocument();
  });

  it('lists each stranded claim with the account that pressed and the age of the claim', async () => {
    vi.mocked(getStrandedEscalations).mockResolvedValue(STUCK);
    mount();
    const oldest = await screen.findByText('ev-ancient');
    const row = oldest.closest('li') as HTMLElement;
    expect(within(row).getByText('analyst')).toBeInTheDocument();
    // The age, not the timestamp: two hours is a request that may still be in
    // flight and four days is an alert nobody can escalate, and the row has to
    // separate those without arithmetic.
    expect(
      within(row).getByText('Escalation sent 4 days ago. Security Onion has not confirmed a case.'),
    ).toBeInTheDocument();
    // An alert no investigation names keeps its id, and says so.
    expect(within(row).getByText(/An alert with no investigation/)).toBeInTheDocument();
    expect(screen.getByText('token:autotriage')).toBeInTheDocument();
  });

  it('says what the rows mean and what clears them, not just their ids', async () => {
    vi.mocked(getStrandedEscalations).mockResolvedValue(STUCK);
    mount();
    await screen.findByText('ev-ancient');
    // A list of alert ids with no sentence attached is a list an operator
    // scrolls past. The actionable facts are that each row is an alert that
    // cannot be escalated, and that the fix is a press rather than a repair.
    expect(
      screen.getByText(
        /soc-ai refuses a new escalation of each alert until Security Onion confirms the outcome\./,
      ),
    ).toBeInTheDocument();
    // The per-claim check settles a claim whose alert left the queue (R5-I5).
    expect(
      screen.getByText(/also settles a claim whose alert has left the queue/i),
    ).toBeInTheDocument();
    // "escalate" is a verb. The panel used it as a noun (R5 STE 6).
    expect(screen.queryByText(/every escalate|later escalate|group escalate/i)).toBeNull();
  });

  it('reports the ledger’s total, and says so when the list is only part of it', async () => {
    vi.mocked(getStrandedEscalations).mockResolvedValue({
      ...STUCK,
      total: 214,
    });
    mount();
    // 214 open, 2 listed. A panel that showed its rows and called that the
    // total would report a ledger with two hundred stuck alerts as a pair.
    const chip = await screen.findByText(/214 unsettled/);
    expect(chip).toHaveTextContent(/2 oldest shown/);
    expect(chip.getAttribute('title') ?? '').toMatch(/214 claims are open/i);
  });

  it('does not claim a cut list when the list is the whole ledger', async () => {
    vi.mocked(getStrandedEscalations).mockResolvedValue(STUCK);
    mount();
    const chip = await screen.findByText(/2 unsettled/);
    expect(chip).not.toHaveTextContent(/oldest shown/);
  });

  it('an empty ledger says what is absent, in two sentences', async () => {
    mount();
    // Two sentences: what is not there, and what that means. The settling
    // window used to follow them and was machinery the reader never asked for.
    expect(await screen.findByText(/nothing is waiting/i)).toBeInTheDocument();
    expect(screen.getByText(/all escalations have an answer/i)).toBeInTheDocument();
    expect(screen.queryByText(/last 15 minutes/i)).toBeNull();
  });

  it('a failed read says it could not tell, and never renders as an empty ledger', async () => {
    vi.mocked(getStrandedEscalations).mockRejectedValue(new Error('boom'));
    mount();
    // The distinction the whole panel exists for, applied to the panel itself:
    // an absence must not be reported as an all-clear.
    expect(await screen.findByText(/could not read the escalation ledger/i)).toBeInTheDocument();
    expect(screen.queryByText(/all escalations have an answer/i)).toBeNull();
  });
});

// The panel listed raw alert ids, which name nothing an operator can act on
// (dogfood 2026-10-06). A claim names the rule and the host of its alert.
describe('Operate escalation-ledger panel names the alert', () => {
  it('names the rule and the host, and keeps the id in the tooltip', async () => {
    vi.mocked(getStrandedEscalations).mockResolvedValue({
      claims: [
        {
          alert_id: 'ev-named',
          escalated_by: 'analyst',
          claimed_at: iso(120 * HOUR),
          rule_name: 'ET MALWARE Beacon',
          host: '192.0.2.10',
        },
      ],
      total: 1,
      settling_minutes: 15,
    });
    mount();
    const rule = await screen.findByText('ET MALWARE Beacon');
    const row = rule.closest('li') as HTMLElement;
    expect(row.textContent).toContain('ET MALWARE Beacon on 192.0.2.10');
    expect(row.textContent).toContain('Escalation sent 5 days ago. Security Onion has not confirmed a case.');
    // The raw id is not on the row. It is in the tooltip for a search.
    expect(within(row).queryByText('ev-named')).toBeNull();
    expect(row.querySelector('[title="Alert ev-named"]')).not.toBeNull();
  });
});

// R5-I5: a stranded claim names an alert the operator has to go and look at.
// There is no alert detail page, so the link opens the Alerts list on that one
// alert: the _id clause, acknowledged alerts shown, and a window around the
// claim. The window starts 31 days before the claim, because the Alerts list
// reaches back at most 30 days and a zone offset can cost one more. It ends a
// day after the claim. A preset such as 30d is relative to now, and a claim
// stays open forever, so a preset loses the alert once the claim is a month old.
describe('Operate escalation-ledger panel links each claim to its alert', () => {
  const localInput = (ms: number) => {
    const d = new Date(ms);
    const p = (n: number) => String(n).padStart(2, '0');
    return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
  };

  it('opens the Alerts list on that alert, in a window around the claim', async () => {
    const claimedAt = iso(40 * 24 * HOUR);
    vi.mocked(getStrandedEscalations).mockResolvedValue({
      claims: [{ alert_id: 'PtyMc6AB-x_1', escalated_by: 'analyst', claimed_at: claimedAt }],
      total: 1,
      settling_minutes: 15,
    });
    mount();
    const link = await screen.findByRole('link', { name: 'Open alert PtyMc6AB-x_1 in Alerts' });
    const href = link.getAttribute('href') ?? '';
    const url = new URL(href, 'http://x');
    expect(url.pathname).toBe('/alerts');
    expect(url.searchParams.get('q')).toBe('_id:"PtyMc6AB-x_1"');
    expect(url.searchParams.get('hide_acked')).toBe('false');
    expect(url.searchParams.get('range')).toBe('custom');
    const claim = Date.parse(claimedAt);
    expect(url.searchParams.get('from')).toBe(localInput(claim - 31 * 24 * HOUR));
    expect(url.searchParams.get('to')).toBe(localInput(claim + 24 * HOUR));
  });

  it('offers no link for an id the filter cannot quote', async () => {
    vi.mocked(getStrandedEscalations).mockResolvedValue({
      claims: [{ alert_id: 'bad"id', escalated_by: 'analyst', claimed_at: iso(2 * HOUR) }],
      total: 1,
      settling_minutes: 15,
    });
    mount();
    await screen.findByText('bad"id');
    expect(screen.queryByRole('link', { name: /open alert/i })).toBeNull();
  });
});
