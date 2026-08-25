// The permalink's back-link is driven by router state, not the id alone —
// a promoted finding is opened from its hunt (Investigate button,
// HuntDetail.tsx) and should return there, labeled "Hunt", rather than to
// the generic Alerts fallback.
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Investigation as Inv } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getInvestigation: vi.fn(),
}));

// Stand-in for the report body — none of its content is under test here.
vi.mock('./Investigation', () => ({
  Investigation: () => <div data-testid="investigation-report" />,
}));

import { getInvestigation } from '../lib/api';
import { InvestigationPage } from './InvestigationPage';

const baseInv: Inv = {
  id: 'INV-1',
  groupId: 'ev-1',
  name: 'Beaconing to rare external IP',
  kind: 'hunt',
  host: '192.0.2.10',
  ip: '198.51.100.7',
  verdict: 'true_positive',
  conf: 0.8,
  rationale: 'promoted finding',
  summary: [],
  status: 'complete',
  elapsedLabel: '1m',
  actions: [],
  timeline: [],
  nodes: [],
  edges: [],
  seedChat: [],
};

const at = (path: string, state?: unknown) =>
  render(
    <MemoryRouter initialEntries={[{ pathname: path, state }]}>
      <Routes>
        <Route path="/investigation/:id" element={<InvestigationPage />} />
      </Routes>
    </MemoryRouter>,
  );

beforeEach(() => {
  vi.mocked(getInvestigation).mockResolvedValue(baseInv);
});

describe('InvestigationPage back-link', () => {
  it('returns to the hunt, labeled "Hunt", when opened from a hunt page', async () => {
    at('/investigation/INV-1', { from: '/hunts/01HUNT0000000000000000000000' });
    const link = await screen.findByRole('link', { name: 'Hunt' });
    expect(link).toHaveAttribute('href', '/hunts/01HUNT0000000000000000000000');
  });

  it('returns to Investigations when opened from the list', async () => {
    at('/investigation/INV-1', { from: '/investigations' });
    const link = await screen.findByRole('link', { name: 'Investigations' });
    expect(link).toHaveAttribute('href', '/investigations');
  });

  it('defaults to Alerts when no from state is given', async () => {
    at('/investigation/INV-1');
    const link = await screen.findByRole('link', { name: 'Alerts' });
    expect(link).toHaveAttribute('href', '/alerts');
  });
});
