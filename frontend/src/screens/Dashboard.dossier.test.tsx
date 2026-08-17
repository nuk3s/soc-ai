// The dossier's "reconsider?" queue is a decision the system is waiting on, and
// it lived only on a screen the operator had no reason to open. GET
// /dossiers/conflicts returns `pending` in the same shape as the detection-tuning
// summary precisely so it can sit beside that nudge here.
//
// Both directions are pinned: it appears when there is something to decide, and
// it is absent (not an empty card) when there isn't — an admin-only endpoint
// that 403s for an analyst resolves to no data, which must read as "nothing to
// see" rather than as a broken panel.
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter, useLocation } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { DossierConflicts } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAlerts: vi.fn().mockResolvedValue([]),
  getQualityEvalStatus: vi.fn().mockResolvedValue({ running: false }),
  listInvestigations: vi.fn().mockResolvedValue({ rows: [], total: 0, running: 0, truePositives: 0, totalAll: 0, active: false, limit: 100, offset: 0 }),
  getAutoTriageStatus: vi.fn().mockResolvedValue({ active: false, hunted: 0, total: 0 }),
  getDataSources: vi.fn().mockResolvedValue({ sources: [] }),
  getQualityTrend: vi.fn().mockResolvedValue({ points: [] }),
  getHealth: vi.fn().mockResolvedValue(null),
  getDetectionTuningSummary: vi.fn().mockResolvedValue(null),
  getDossierConflicts: vi.fn(),
}));

import { getDossierConflicts } from '../lib/api';
import { Dashboard } from './Dashboard';

const conflicts = (pending: number): DossierConflicts => ({ pending, rows: [] });

function Here() {
  const loc = useLocation();
  return <div data-testid="here">{loc.pathname + loc.search}</div>;
}

const mount = () =>
  render(
    <MemoryRouter initialEntries={['/']}>
      <Dashboard />
      <Here />
    </MemoryRouter>,
  );

const here = () => screen.getByTestId('here').textContent;

beforeEach(() => {
  vi.mocked(getDossierConflicts).mockReset().mockResolvedValue(conflicts(0));
});

describe('Dashboard host-dossier nudge', () => {
  it('surfaces the pending disagreements and opens the queue', async () => {
    vi.mocked(getDossierConflicts).mockResolvedValue(conflicts(3));
    mount();
    expect(await screen.findByText(/3 disagreements/i)).toBeTruthy();
    fireEvent.click(screen.getByRole('button', { name: /review/i }));
    // ?conflicts=1 seeds the queue OPEN on arrival — landing on the host table
    // with the queue collapsed would drop the operator one click short of the
    // thing the nudge promised.
    expect(here()).toBe('/hosts?conflicts=1');
  });

  it('says nothing when the lanes agree', async () => {
    mount();
    // Wait for a settled Dashboard before asserting an absence.
    await screen.findByText('Investigation outcomes');
    expect(screen.queryByText(/disagreements? need/i)).toBeNull();
  });
});
