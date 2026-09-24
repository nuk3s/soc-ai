// The permalink's back-link is driven by router state, not the id alone —
// a promoted finding is opened from its hunt (Investigate button,
// HuntDetail.tsx) and should return there, labeled "Hunt", rather than to
// the generic Alerts fallback.
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { Investigation as Inv, InvestigationSubject } from '../lib/types';

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

/** A run whose subject is a hunt. It has no alert behind it, so the Alerts
 *  console holds nothing it read. */
const SUBJECT: InvestigationSubject = {
  type: 'hunt',
  hunt_id: '01HUNT0000000000000000000000',
  objective: 'Sweep for directory replication by a non-machine account',
  finding_ordinals: [0],
  lead_id: 10,
  document_ids: ['doc-a'],
  observation_ids: [41],
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

  // A hunt subject has no alert behind it. The breadcrumb read "Alerts /
  // Investigation" and sent the analyst to a console that holds nothing this
  // run read.
  it('goes to Hunts on a run whose subject is a hunt', async () => {
    vi.mocked(getInvestigation).mockResolvedValue({ ...baseInv, subject: SUBJECT });
    at('/investigation/INV-1');
    const link = await screen.findByRole('link', { name: 'Hunts' });
    expect(link).toHaveAttribute('href', '/hunts');
  });

  // An origin the analyst came from wins over the list of every hunt.
  it('keeps the hunt it was opened from', async () => {
    vi.mocked(getInvestigation).mockResolvedValue({ ...baseInv, subject: SUBJECT });
    at('/investigation/INV-1', { from: '/hunts/01HUNT0000000000000000000000' });
    const link = await screen.findByRole('link', { name: 'Hunt' });
    expect(link).toHaveAttribute('href', '/hunts/01HUNT0000000000000000000000');
  });
});
