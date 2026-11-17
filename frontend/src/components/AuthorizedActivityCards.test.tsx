// The cards of authorized activity. A run inside an authorized scope raises
// no notification of its own, so the card is where the analyst sees it: the
// label, the scope, the expiry and the count of its runs. Revoke asks for a
// reason before it writes.
import { cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { AuthorizedActivity } from '../lib/api';

const listMock = vi.hoisted(() => vi.fn());
const revokeMock = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAuthorizedActivity: listMock,
  revokeAuthorizedActivity: revokeMock,
}));

import { AuthorizedActivityCards } from './AuthorizedActivityCards';
import { forbiddenWords } from '../test/analystWords';

const record = (over: Partial<AuthorizedActivity> = {}): AuthorizedActivity => ({
  id: 3,
  label: 'php2shell test',
  note: null,
  state: 'active',
  sources: [
    { address: '10.50.0.26', name: 'agent-a', machine_key: 'agent:a-1', identity: 'agent' },
    { address: '10.50.0.52', name: null, machine_key: null, identity: 'address' },
  ],
  target: { address: '10.40.0.164', name: null, machine_key: 'ip:10.40.0.164', identity: 'address' },
  rule_names: [
    'ET EXPLOIT PHP php2shell Nested Empty File Control OOM (CVE-2026-109618)',
    'ET EXPLOIT PHP php2shell Multipart Header Amplification OOM (CVE-2026-109618)',
  ],
  rule_class: 'exploit_attempt',
  starts_at: '2026-11-13T10:00:00+00:00',
  expires_at: '2099-01-01T00:00:00+00:00',
  created_at: '2026-11-13T10:00:00+00:00',
  created_by: 'casey',
  revoked_at: null,
  revoked_by: null,
  revoke_reason: null,
  source_investigation_id: 'INV-1',
  runs_since_decision: 4,
  earlier_runs: 2,
  runs_total: 6,
  last_match_at: null,
  runs_href: '/investigations?authorization=3&range=all',
  ...over,
});

const mount = () =>
  render(
    <MemoryRouter>
      <AuthorizedActivityCards />
    </MemoryRouter>,
  );

afterEach(() => {
  cleanup();
  listMock.mockReset();
  revokeMock.mockReset();
});

describe('the authorized activity cards', () => {
  it('shows one card with the scope, the state and the count of its runs on one row', async () => {
    listMock.mockResolvedValue({ rows: [record()], active: 1 });
    mount();
    const card = await screen.findByTestId('authorized-card-3');
    const row = screen.getByTestId('authorized-row');
    expect(row.textContent).toContain('php2shell test');
    expect(screen.getByTestId('authorized-state').textContent).toBe('Active');
    // The sources by name and the target. The whole scope is in the title.
    const scope = screen.getByTestId('authorized-scope');
    expect(scope.textContent).toBe('agent-a, 10.50.0.52 to 10.40.0.164');
    expect(scope.getAttribute('title')).toBe('Sources: agent-a at 10.50.0.26, 10.50.0.52. Target: 10.40.0.164.');
    const expiry = screen.getByTestId('authorized-expiry');
    expect(expiry.textContent).toMatch(/^Expires in [\d,]+ days$/);
    expect(expiry.getAttribute('title')).toContain('casey recorded it on 2026-11-13 10:00 UTC.');
    const link = screen.getByTestId('authorized-runs-link');
    expect(link.textContent).toBe('4 matching investigations since the decision, and 2 earlier investigations');
    expect(link.getAttribute('href')).toBe('/investigations?authorization=3&range=all');
    expect(within(row).getByRole('button', { name: 'Revoke' })).toBeTruthy();
    expect(screen.getByRole('heading', { name: 'Authorized activity' })).toBeTruthy();
    // The card is full width: no two-column grid.
    expect(card.parentElement?.className).not.toMatch(/grid-cols-2/);
  });

  it('keeps the rules behind a toggle that is closed by default', async () => {
    listMock.mockResolvedValue({ rows: [record({ note: 'The red team owns this test.' })], active: 1 });
    mount();
    await screen.findByTestId('authorized-card-3');
    // NEGATIVE CONTROL: closed, the card names no rule.
    expect(screen.queryByTestId('authorized-rules')).toBeNull();
    expect(screen.getByTestId('authorized-card-3').textContent).not.toContain('Nested Empty File');
    const toggle = screen.getByRole('button', { name: 'Show the 2 rules' });
    expect(toggle.getAttribute('aria-expanded')).toBe('false');
    fireEvent.click(toggle);
    const rules = screen.getByTestId('authorized-rules');
    expect(rules.textContent).toContain('2 rules, class exploit attempt:');
    expect(rules.querySelectorAll('li')).toHaveLength(2);
    expect(rules.textContent).toContain(
      'ET EXPLOIT PHP php2shell Multipart Header Amplification OOM (CVE-2026-109618)',
    );
    expect(rules.textContent).toContain('casey recorded it on 2026-11-13 10:00 UTC.');
    expect(rules.textContent).toContain('Note: The red team owns this test.');
    fireEvent.click(screen.getByRole('button', { name: 'Hide the rules' }));
    expect(screen.queryByTestId('authorized-rules')).toBeNull();
  });

  // The owner's rule (2026-11-14): no "run" for an investigation on the card.
  it('holds no forbidden word with the rules open and the revoke form open', async () => {
    listMock.mockResolvedValue({ rows: [record({ note: 'The red team owns this test.' })], active: 1 });
    const { container } = mount();
    await screen.findByTestId('authorized-card-3');
    fireEvent.click(screen.getByRole('button', { name: 'Show the 2 rules' }));
    fireEvent.click(screen.getByRole('button', { name: 'Revoke' }));
    expect(forbiddenWords(container)).toEqual([]);
  });

  it('renders nothing when no record is in force', async () => {
    listMock.mockResolvedValue({ rows: [], active: 0 });
    const { container } = mount();
    await waitFor(() => expect(listMock).toHaveBeenCalled());
    expect(container.textContent).toBe('');
    expect(screen.queryByTestId('authorized-cards')).toBeNull();
  });

  it('says that the read failed, and never shows an empty list for a failure', async () => {
    listMock.mockRejectedValue(new Error('down'));
    mount();
    expect((await screen.findByTestId('authorized-cards-error')).textContent).toBe(
      'soc-ai could not read the authorized activity.',
    );
  });

  it('asks for a reason before a revoke, and then reads the list again', async () => {
    listMock.mockResolvedValue({ rows: [record()], active: 1 });
    revokeMock.mockResolvedValue(record({ state: 'revoked', runs_returned: 6 }));
    mount();
    fireEvent.click(await screen.findByRole('button', { name: 'Revoke' }));
    // The first press writes nothing.
    expect(revokeMock).not.toHaveBeenCalled();
    const confirm = screen.getByRole('button', { name: 'Confirm revoke' });
    expect(confirm).toBeDisabled();
    expect(screen.getByTestId('authorized-revoke-form').textContent).toContain(
      'Its investigations get normal handling again',
    );
    fireEvent.change(screen.getByLabelText('Reason for the revoke'), {
      target: { value: '  The test ended.  ' },
    });
    expect(confirm).not.toBeDisabled();
    fireEvent.click(confirm);
    await waitFor(() => expect(revokeMock).toHaveBeenCalledWith(3, 'The test ended.'));
    await waitFor(() => expect(listMock).toHaveBeenCalledTimes(2));
  });

  it('keeps the form and shows the reason of a failed revoke', async () => {
    listMock.mockResolvedValue({ rows: [record()], active: 1 });
    revokeMock.mockRejectedValue(new Error('An analyst revoked this authorized activity before.'));
    mount();
    fireEvent.click(await screen.findByRole('button', { name: 'Revoke' }));
    fireEvent.change(screen.getByLabelText('Reason for the revoke'), { target: { value: 'x' } });
    fireEvent.click(screen.getByRole('button', { name: 'Confirm revoke' }));
    expect((await screen.findByRole('alert')).textContent).toBe(
      'An analyst revoked this authorized activity before.',
    );
    expect(screen.getByTestId('authorized-revoke-form')).toBeTruthy();
  });

  it('offers no revoke on a revoked record, and one on an expired record', async () => {
    listMock.mockResolvedValue({
      rows: [
        record({
          id: 4,
          state: 'revoked',
          revoked_by: 'dana',
          revoked_at: '2026-11-15T08:00:00+00:00',
          revoke_reason: 'The test ended.',
        }),
        record({ id: 5, state: 'expired', expires_at: '2026-11-12T10:00:00+00:00' }),
      ],
      active: 0,
    });
    mount();
    const revoked = await screen.findByTestId('authorized-card-4');
    expect(within(revoked).getByTestId('authorized-expiry').textContent).toBe(
      'Revoked by dana on 2026-11-15 08:00 UTC',
    );
    expect(within(revoked).getByTestId('authorized-expiry').getAttribute('title')).toContain(
      'dana revoked it on 2026-11-15 08:00 UTC. Reason: The test ended.',
    );
    expect(within(revoked).queryByRole('button', { name: 'Revoke' })).toBeNull();
    const expired = screen.getByTestId('authorized-card-5');
    expect(within(expired).getByTestId('authorized-expiry').textContent).toBe('Expired on 2026-11-12 10:00 UTC');
    expect(within(expired).getByTestId('authorized-expiry').getAttribute('title')).toContain(
      'New investigations get normal handling.',
    );
    expect(within(expired).getByRole('button', { name: 'Revoke' })).toBeTruthy();
  });
});
