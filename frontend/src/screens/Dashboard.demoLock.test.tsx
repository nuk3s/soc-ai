// The demo read lock (SOC_AI_DEMO) makes admin-gated GETs answer 403. Two of the
// Dashboard's panels are backed by such GETs — Enrichment posture
// (/config/data-sources) and Verdict quality (/quality/trend) — so under the lock
// they must degrade to a neutral "not shown in the demo" line, NOT the "Sign in
// as an admin" prompt (there is no admin to sign in as on a public demo) and NOT
// a scary error card. See finding demo-admin-reads-anonymous.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import { DemoProvider } from '../lib/demo';

// Same api mock shape as Dashboard.test.tsx (the net guard rejects any unmocked
// fetch), but the two admin-gated reads REJECT with a 403 — exactly what the demo
// lock returns for them.
vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAlerts: vi.fn().mockResolvedValue([]),
  getDossierConflicts: vi.fn().mockResolvedValue({ pending: 0, rows: [] }),
  getQualityEvalStatus: vi.fn().mockResolvedValue({ running: false }),
  listInvestigations: vi.fn().mockResolvedValue({
    rows: [],
    total: 0,
    running: 0,
    truePositives: 0,
    totalAll: 0,
    active: false,
    limit: 100,
    offset: 0,
  }),
  getAutoTriageStatus: vi.fn().mockResolvedValue({ active: false, hunted: 0, total: 0 }),
  getHealth: vi.fn().mockResolvedValue(null),
  startQualityEval: vi.fn(),
  getDataSources: vi.fn().mockRejectedValue(new Error('403 Forbidden')),
  getQualityTrend: vi.fn().mockRejectedValue(new Error('403 Forbidden')),
}));

import { Dashboard } from './Dashboard';

describe('Dashboard under the demo read lock', () => {
  it('degrades the two admin-gated panels to a neutral demo line — no admin prompt, no error card', async () => {
    render(
      <MemoryRouter>
        <DemoProvider demo>
          <Dashboard />
        </DemoProvider>
      </MemoryRouter>,
    );
    // Both panels render their neutral demo line once the 403 lands…
    expect(
      await screen.findByText(/Enrichment posture is an admin-only view/),
    ).toBeInTheDocument();
    expect(await screen.findByText(/Quality history is an admin-only view/)).toBeInTheDocument();
    // …and never the admin-login prompt (unfollowable on a public demo).
    expect(screen.queryByText(/Sign in as an admin/)).toBeNull();
  });
});
