// Dogfood 2026-10-19, R5-I5: "Escalations awaiting an answer" listed each
// stranded claim and could do nothing about it. Only a group escalation that
// covers the alert compared a claim with Security Onion, so a claim whose
// alert left the queue stayed open for good. Each row now has "Check Security
// Onion now", which asks the server to compare that one claim with Security
// Onion and states the result in one sentence.
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getStrandedEscalations: vi.fn(),
  checkEscalationClaim: vi.fn(),
}));

import {
  ApiError,
  checkEscalationClaim,
  getStrandedEscalations,
  type EscalationCheck,
  type StrandedClaims,
} from '../lib/api';
import { EscalationLedgerPanel } from './EscalationLedgerPanel';

const HOUR = 3_600_000;
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();

const STUCK: StrandedClaims = {
  claims: [
    {
      alert_id: 'ev-one',
      escalated_by: 'analyst',
      claimed_at: iso(30 * HOUR),
      rule_name: 'ET POLICY example one',
      host: 'host-a.example.com',
    },
    {
      alert_id: 'ev-two',
      escalated_by: 'analyst',
      claimed_at: iso(5 * HOUR),
      rule_name: 'ET POLICY example two',
      host: null,
    },
  ],
  total: 2,
  settling_minutes: 15,
};

const AFTER_SETTLE: StrandedClaims = { ...STUCK, claims: [STUCK.claims[1]], total: 1 };

const mount = () =>
  render(
    <MemoryRouter>
      <EscalationLedgerPanel />
    </MemoryRouter>,
  );

/** The row of a claim. The result line also names the rule, outside the list. */
function rowOf(rule: string): HTMLElement {
  return screen.getByText(rule, { selector: 'li *' }).closest('li') as HTMLElement;
}

beforeEach(() => {
  vi.mocked(getStrandedEscalations).mockReset().mockResolvedValue(STUCK);
  vi.mocked(checkEscalationClaim).mockReset();
});

describe('Check Security Onion now', () => {
  it('offers the check on each row', async () => {
    mount();
    await screen.findByText('ET POLICY example one');
    expect(
      within(rowOf('ET POLICY example one')).getByRole('button', { name: 'Check Security Onion now' }),
    ).toBeEnabled();
    expect(
      within(rowOf('ET POLICY example two')).getByRole('button', { name: 'Check Security Onion now' }),
    ).toBeEnabled();
  });

  it('settles a claim, states the result and reads the ledger again', async () => {
    const settled: EscalationCheck = {
      alert_id: 'ev-one',
      result: 'case_found',
      settled: true,
      case_id: 'case-7',
      case_url: 'https://so.example/#/case/case-7',
      message: 'soc-ai found case case-7 for alert ev-one. The claim is settled.',
    };
    vi.mocked(checkEscalationClaim).mockResolvedValue(settled);
    mount();
    await screen.findByText('ET POLICY example one');
    vi.mocked(getStrandedEscalations).mockResolvedValue(AFTER_SETTLE);

    fireEvent.click(
      within(rowOf('ET POLICY example one')).getByRole('button', { name: 'Check Security Onion now' }),
    );

    expect(checkEscalationClaim).toHaveBeenCalledWith('ev-one');
    const status = await screen.findByTestId('escalation-check-result');
    // One sentence of fact, one of state, and the case is a link (V3 STE).
    expect(status.textContent).toBe('soc-ai found case case-7 for alert ev-one. The claim is settled.');
    expect(within(status).getByRole('link', { name: 'case-7' })).toHaveAttribute(
      'href',
      'https://so.example/#/case/case-7',
    );
    await waitFor(() => expect(getStrandedEscalations).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(screen.queryByText('ET POLICY example one', { selector: 'li *' })).toBeNull());
  });

  it('states a claim that stays open and keeps its row', async () => {
    vi.mocked(checkEscalationClaim).mockResolvedValue({
      alert_id: 'ev-two',
      result: 'waiting',
      settled: false,
      case_id: null,
      message:
        'The claim stays open. Security Onion marks the alert as escalated and shows no case link.',
    });
    mount();
    await screen.findByText('ET POLICY example two');

    fireEvent.click(
      within(rowOf('ET POLICY example two')).getByRole('button', { name: 'Check Security Onion now' }),
    );

    expect(await screen.findByTestId('escalation-check-result')).toHaveTextContent(
      'The claim stays open. Security Onion marks the alert as escalated and shows no case link.',
    );
    expect(getStrandedEscalations).toHaveBeenCalledTimes(1);
    expect(rowOf('ET POLICY example two')).toBeInTheDocument();
  });

  it('states that Security Onion did not answer', async () => {
    vi.mocked(checkEscalationClaim).mockRejectedValue(
      new ApiError('The claim stays open. Security Onion did not answer.', 503, 'grid_unavailable'),
    );
    mount();
    await screen.findByText('ET POLICY example one');

    fireEvent.click(
      within(rowOf('ET POLICY example one')).getByRole('button', { name: 'Check Security Onion now' }),
    );

    expect(await screen.findByTestId('escalation-check-result')).toHaveTextContent(
      'The claim stays open. Security Onion did not answer.',
    );
    expect(getStrandedEscalations).toHaveBeenCalledTimes(1);
  });

  it('disables every check while one runs', async () => {
    let finish: (v: EscalationCheck) => void = () => {};
    vi.mocked(checkEscalationClaim).mockImplementation(
      () =>
        new Promise<EscalationCheck>((resolve) => {
          finish = resolve;
        }),
    );
    mount();
    await screen.findByText('ET POLICY example one');

    fireEvent.click(
      within(rowOf('ET POLICY example one')).getByRole('button', { name: 'Check Security Onion now' }),
    );

    const running = within(rowOf('ET POLICY example one')).getByRole('button', {
      name: 'Checking Security Onion',
    });
    expect(running).toBeDisabled();
    const other = within(rowOf('ET POLICY example two')).getByRole('button', {
      name: 'Check Security Onion now',
    });
    expect(other).toBeDisabled();
    fireEvent.click(other);
    expect(checkEscalationClaim).toHaveBeenCalledTimes(1);

    await act(async () => {
      finish({
        alert_id: 'ev-one',
        result: 'waiting',
        settled: false,
        case_id: null,
        message: 'The escalation is less than 15 minutes old, so the claim stays open.',
      });
    });
    expect(
      within(rowOf('ET POLICY example two')).getByRole('button', { name: 'Check Security Onion now' }),
    ).toBeEnabled();
  });

  it('says what the check does in the panel footer', async () => {
    mount();
    await screen.findByText('ET POLICY example one');
    expect(
      screen.getByText(/Select Check Security Onion now to compare one claim with Security Onion\./),
    ).toBeInTheDocument();
  });
});
