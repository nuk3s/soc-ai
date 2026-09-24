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
// read; a failed read must read as "couldn't tell" and NOT as an empty list;
// and the count must be the ledger's, not the list's, because a capped list
// reporting its own length is the same silent under-report all over again.
import { render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getHuntCatalog: vi.fn(),
  getStrandedEscalations: vi.fn(),
}));

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
    expect(within(row).getByText(/claimed 4d ago/i)).toBeInTheDocument();
    expect(screen.getByText('token:autotriage')).toBeInTheDocument();
  });

  it('says what the rows mean and what clears them, not just their ids', async () => {
    vi.mocked(getStrandedEscalations).mockResolvedValue(STUCK);
    mount();
    await screen.findByText('ev-ancient');
    // A list of alert ids with no sentence attached is a list an operator
    // scrolls past. The actionable facts are that each row is an alert that
    // cannot be escalated, and that the fix is a press rather than a repair.
    expect(screen.getByText(/refused by every escalate/i)).toBeInTheDocument();
    expect(screen.getByText(/will not settle on its own/i)).toBeInTheDocument();
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
    expect(await screen.findByText(/couldn't read the escalation ledger/i)).toBeInTheDocument();
    expect(screen.queryByText(/all escalations have an answer/i)).toBeNull();
  });
});
