// Dogfood 2026-10-06 W9: an analytic went live after 0 sweeps. The approve
// box asked for "Why it goes live" and nothing else, and the drawer of a
// shadow analytic named no end of the shadow week.
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAnalytic: vi.fn(),
  setAnalyticStatus: vi.fn(),
}));

import { getAnalytic, setAnalyticStatus, type AnalyticDetail, type AnalyticRow } from '../lib/api';
import { ShellProvider } from '../shell/ShellContext';
import { AnalyticActions, AnalyticDrawer, shadowRecordLine } from './AnalyticDrawer';

const DAY = 86_400_000;
const iso = (ms: number) => new Date(ms).toISOString();

const row: AnalyticRow = {
  id: 'local-http-service-executes-id',
  title: 't',
  level: 'high',
  evaluator: 'match',
  scope_kind: 'host',
  tier: 'local',
  status: 'shadow',
  observations_7d: 0,
  leads_7d: 0,
  hunted_7d: 0,
  dismissed_7d: 0,
  shadow_hits_7d: 0,
  unread_shadow_hits: 0,
} as AnalyticRow;

function withRecord(endsInDays: number): AnalyticDetail {
  return {
    ...row,
    shadow_since: iso(Date.now() + (endsInDays - 7) * DAY),
    shadow_ends_at: iso(Date.now() + endsInDays * DAY),
    shadow_sweeps: 0,
    shadow_hits: 0,
  } as AnalyticDetail;
}

const mount = (analytic: AnalyticRow) =>
  render(
    <MemoryRouter>
      <AnalyticActions analytic={analytic} />
    </MemoryRouter>,
  );

function approveWith(reason: string) {
  fireEvent.click(screen.getByRole('button', { name: 'Approve' }));
  fireEvent.change(screen.getByPlaceholderText('Why it goes live'), { target: { value: reason } });
}

describe('approve and the shadow week', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(setAnalyticStatus).mockResolvedValue(row);
  });

  it('states the record and asks twice while the shadow week runs', async () => {
    const analytic = withRecord(6);
    mount(analytic);
    approveWith('looks right');
    const line = screen.getByTestId('approve-shadow-record').textContent ?? '';
    expect(line).toMatch(/^Shadow record: 0 sweeps, 0 hits\. The shadow week ends on \d{4}-\d{2}-\d{2}\.$/);
    expect(line).toContain(analytic.shadow_ends_at!.slice(0, 10));
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    expect(setAnalyticStatus).not.toHaveBeenCalled();
    expect(screen.getByTestId('approve-early').textContent).toContain('The shadow week is not over.');
    fireEvent.click(screen.getByRole('button', { name: 'Approve anyway' }));
    await waitFor(() =>
      expect(setAnalyticStatus).toHaveBeenCalledWith(analytic.id, 'live', 'looks right'),
    );
  });

  it('asks once after the shadow week', async () => {
    // Negative control: a week that ended needs no second confirm.
    mount(withRecord(-1));
    approveWith('a week of clean hits');
    expect(screen.getByTestId('approve-shadow-record').textContent).toContain('ended on');
    fireEvent.click(screen.getByRole('button', { name: 'Confirm' }));
    await waitFor(() => expect(setAnalyticStatus).toHaveBeenCalledTimes(1));
    expect(screen.queryByTestId('approve-early')).toBeNull();
  });

  it('reads the record from the server for a list row', async () => {
    vi.mocked(getAnalytic).mockResolvedValue(withRecord(5));
    mount(row);
    fireEvent.click(screen.getByRole('button', { name: 'Approve' }));
    await waitFor(() => expect(getAnalytic).toHaveBeenCalledWith(row.id));
    expect((await screen.findByTestId('approve-shadow-record')).textContent).toContain(
      'Shadow record: 0 sweeps, 0 hits.',
    );
  });

  it('states the hits and the sweeps in words', () => {
    expect(
      shadowRecordLine({ sweeps: 1, hits: 2, endsAt: '2026-10-12T08:00:00Z' }, Date.parse('2026-10-06T00:00:00Z')),
    ).toBe('Shadow record: 1 sweep, 2 hits. The shadow week ends on 2026-10-12.');
    expect(shadowRecordLine({ sweeps: 3, hits: 0, endsAt: null })).toBe(
      'Shadow record: 3 sweeps, 0 hits.',
    );
  });

  it('names the end of the shadow week in the drawer', async () => {
    const detail = {
      ...withRecord(4),
      description: 'd',
      spec_text: 'id: x\n',
      reason: null,
      ledger: {
        analytic_id: row.id,
        since: iso(Date.now() - 30 * DAY),
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
    } as unknown as AnalyticDetail;
    vi.mocked(getAnalytic).mockResolvedValue(detail);
    render(
      <MemoryRouter>
        <ShellProvider>
          <AnalyticDrawer analyticId={row.id} onClose={() => {}} />
        </ShellProvider>
      </MemoryRouter>,
    );
    expect((await screen.findByTestId('analytic-shadow-week')).textContent).toContain(
      `The shadow week ends on ${detail.shadow_ends_at!.slice(0, 10)}.`,
    );
  });
});
