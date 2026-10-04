// The Dashboard tuning nudge said "29 mute suggestions pending" while its
// Review target listed 39 nominated rules with no count (D10). The nudge now
// names both numbers, so the two surfaces agree.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getAlerts: vi.fn().mockResolvedValue({ groups: [], truncated: false, other_docs: 0 }),
  getDossierConflicts: vi.fn().mockResolvedValue({ pending: 0, rows: [] }),
  getQualityEvalStatus: vi.fn().mockResolvedValue({ running: false }),
  listInvestigations: vi.fn().mockResolvedValue({ rows: [], total: 0, running: 0, truePositives: 0, totalAll: 0, active: false, limit: 100, offset: 0 }),
  getAutoTriageStatus: vi.fn().mockResolvedValue({ active: false, hunted: 0, total: 0 }),
  getDataSources: vi.fn().mockResolvedValue({ sources: [] }),
  getQualityTrend: vi.fn().mockResolvedValue({ points: [] }),
  getHealth: vi.fn().mockResolvedValue(null),
  getDetectionTuningSummary: vi.fn().mockResolvedValue({ pending: 29, nominated: 39 }),
  // Setup-health card: unconditional on mount, so every Dashboard-rendering
  // test needs it named or the global fetch guard rejects loudly. Green here
  // (this file isn't about setup health), so the admin-only detail read is
  // never reached regardless of role.
  getMe: vi.fn().mockResolvedValue({ username: 'ana', role: 'analyst', status: '' }),
  getPreflight: vi.fn().mockResolvedValue({ status: 'green', failing: 0, warned: 0, checked_at: '2026-08-19T00:00:00+00:00' }),
  getPreflightDetail: vi.fn().mockResolvedValue({ rows: [], checked_at: '2026-08-19T00:00:00+00:00' }),
}));

import { Dashboard } from './Dashboard';
import { getDetectionTuningSummary } from '../lib/api';

const mount = () =>
  render(
    <MemoryRouter initialEntries={['/']}>
      <Dashboard />
    </MemoryRouter>,
  );

describe('Dashboard tuning nudge', () => {
  it('names the nominated rules and the mute suggestions among them', async () => {
    mount();
    const line = await screen.findByTestId('tuning-nudge-count');
    expect(line.textContent).toBe('39 nominated rules · 29 mute suggestions');
  });

  it('keeps the mute count alone for a backend that sends no rule count', async () => {
    vi.mocked(getDetectionTuningSummary).mockResolvedValue({ pending: 1 });
    mount();
    const line = await screen.findByTestId('tuning-nudge-count');
    expect(line.textContent).toBe('1 mute suggestion');
  });
});
