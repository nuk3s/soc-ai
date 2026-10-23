// The permalink's back link names the page the analyst left. The shell holds
// it in `previousPage`, with its search. A promoted finding opened from its
// hunt (Investigate button, HuntDetail.tsx) also sends the hunt path in the
// router state, and that state outlives a reload. With neither, the link goes
// to the list of investigations.
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes, useNavigate } from 'react-router-dom';
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
import { PreviousPageTracker } from '../shell/PreviousPageTracker';
import { ShellProvider } from '../shell/ShellContext';
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
    const link = await screen.findByRole('link', { name: 'Back to Hunt' });
    expect(link).toHaveAttribute('href', '/hunts/01HUNT0000000000000000000000');
  });

  it('defaults to Investigations when nothing names the page before', async () => {
    at('/investigation/INV-1');
    const link = await screen.findByRole('link', { name: 'Back to Investigations' });
    expect(link).toHaveAttribute('href', '/investigations');
  });

  // A hunt subject has no alert behind it. The list of investigations holds
  // the run, and the Alerts console holds nothing it read.
  it('defaults to Investigations on a run whose subject is a hunt', async () => {
    vi.mocked(getInvestigation).mockResolvedValue({ ...baseInv, subject: SUBJECT });
    at('/investigation/INV-1');
    const link = await screen.findByRole('link', { name: 'Back to Investigations' });
    expect(link).toHaveAttribute('href', '/investigations');
    expect(screen.queryByRole('link', { name: /Alerts/ })).toBeNull();
  });

  it('keeps the hunt it was opened from', async () => {
    vi.mocked(getInvestigation).mockResolvedValue({ ...baseInv, subject: SUBJECT });
    at('/investigation/INV-1', { from: '/hunts/01HUNT0000000000000000000000' });
    const link = await screen.findByRole('link', { name: 'Back to Hunt' });
    expect(link).toHaveAttribute('href', '/hunts/01HUNT0000000000000000000000');
  });
});

/** A page with one button that opens the run, inside the shell and its
 *  previous-page tracker. */
function Opener() {
  const navigate = useNavigate();
  return <button onClick={() => navigate('/investigation/INV-1')}>open the run</button>;
}

const inShell = (start: string) =>
  render(
    <MemoryRouter initialEntries={[start]}>
      <ShellProvider>
        <PreviousPageTracker />
        <Routes>
          <Route path="/investigation/:id" element={<InvestigationPage />} />
          <Route path="*" element={<Opener />} />
        </Routes>
      </ShellProvider>
    </MemoryRouter>,
  );

describe('InvestigationPage back-link reads the page the analyst left', () => {
  it('returns to Alerts with its filter', async () => {
    inShell('/alerts?range=30d');
    act(() => screen.getByText('open the run').click());
    const link = await screen.findByRole('link', { name: 'Back to Alerts' });
    expect(link).toHaveAttribute('href', '/alerts?range=30d');
  });

  it('returns to the lead it came from', async () => {
    inShell('/leads/18');
    act(() => screen.getByText('open the run').click());
    const link = await screen.findByRole('link', { name: 'Back to Lead 18' });
    expect(link).toHaveAttribute('href', '/leads/18');
  });

  // The page the analyst left wins over the list, the default.
  it('returns to Investigations with its window', async () => {
    inShell('/investigations?range=7d');
    act(() => screen.getByText('open the run').click());
    const link = await screen.findByRole('link', { name: 'Back to Investigations' });
    expect(link).toHaveAttribute('href', '/investigations?range=7d');
  });
});

// Dogfood 2026-10-06, first hour C10: the title was the id, and Delete sat
// next to the status as a plain button.
describe('InvestigationPage title and Delete', () => {
  it('reads the rule name as the title, with the id beside it', async () => {
    at('/investigation/INV-1');
    // The title reads "Investigation" until the read lands.
    await waitFor(() =>
      expect(screen.getByTestId('investigation-page-title').textContent).toBe('Beaconing to rare external IP'),
    );
    expect(screen.getByTestId('investigation-page-id').textContent).toBe('INV-1');
  });

  it('keeps Delete in the More menu, behind a confirm', async () => {
    at('/investigation/INV-1');
    await screen.findByTestId('investigation-report');
    // Negative control: no Delete button on the header itself.
    expect(screen.queryByRole('button', { name: /Delete/ })).toBeNull();
    fireEvent.click(screen.getByTestId('investigation-more'));
    fireEvent.click(screen.getByRole('menuitem', { name: /Delete investigation/ }));
    expect(screen.getByRole('button', { name: /Confirm delete/ })).toBeTruthy();
  });
});
