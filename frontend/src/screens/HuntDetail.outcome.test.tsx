// Dogfood 2026-10-06 S1: a hunt that could not run or could not answer read
// "No threat observed". A catalog run that the grid refused wore a green
// "Complete" chip, a "medium" severity chip and an Investigate button on its
// failure record. A free-text hunt whose narrative said the answer "cannot be
// confirmed or ruled out" wore a 0.75 confidence ring.
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AboutInfo, HuntDetailData } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getHunt: vi.fn(),
  getHunts: vi.fn().mockResolvedValue([]),
  getLead: vi.fn(),
  promoteFinding: vi.fn(),
  getHuntChat: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  postHuntChat: vi.fn(),
  getAbout: vi.fn(),
}));

import { getAbout, getHunt } from '../lib/api';
import { HuntDetail, isRunFailure, pageOutcome as huntOutcome } from './HuntDetail';

const about: AboutInfo = {
  version: '1.0.0',
  repo_url: 'https://example.test/soc-ai',
  license: 'MIT',
  update_check_enabled: false,
  general_chat_enabled: true,
  sigma_authoring_enabled: false,
};

const RUN_FAILURE = {
  title: 'Directory replication by a non-machine account: could not run',
  detail: 'The spec failed against the grid. The result is unknown.',
  severity: 'medium',
  category: 'visibility_gap',
  hosts: [] as string[],
  citations: [] as string[],
};

function hunt(over: Partial<HuntDetailData>): HuntDetailData {
  return {
    id: 'H-1',
    objective: '[catalog] identity-4662: Directory replication (now-1440m → now)',
    kind: 'triggered',
    status: 'complete',
    narrative: '',
    findings: [],
    affectedHosts: [],
    mitreTechniques: [],
    recommendedActions: [],
    confidence: null,
    startedBy: 'hunt-catalog',
    elapsedLabel: '2s',
    elapsedSec: 2,
    ts: '2026-10-06T00:00:00Z',
    timeline: [],
    diff: null,
    ...over,
  };
}

function mount() {
  return render(
    <MemoryRouter initialEntries={['/hunts/H-1']}>
      <Routes>
        <Route path="/hunts/:id" element={<HuntDetail />} />
      </Routes>
    </MemoryRouter>,
  );
}

describe('HuntDetail outcome', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getAbout).mockResolvedValue(about);
  });

  it('reads Could not run on a catalog run the grid refused', async () => {
    vi.mocked(getHunt).mockResolvedValue(
      hunt({
        findings: [RUN_FAILURE],
        outcome: 'could_not_run',
        outcome_label: 'Could not run',
        outcome_headline:
          'The grid did not accept a connection. Hunt again when the grid is healthy.',
        title: 'Directory replication, last 24 h',
      }),
    );
    mount();
    const badge = await screen.findByTestId('hunt-disposition');
    expect(badge.textContent).toBe('Could not run');
    expect(screen.getByTestId('hunt-outcome-headline').textContent).toBe(
      'The grid did not accept a connection. Hunt again when the grid is healthy.',
    );
    // The plain title the bell and the list read, with no prefix and no date math.
    expect(screen.getByTestId('hunt-title').textContent).toBe('Directory replication, last 24 h');
    // No green Complete chip, no severity chip, no promotion, no chart.
    expect(screen.queryByText('Complete')).toBeNull();
    expect(screen.queryByTestId('finding-severity')).toBeNull();
    expect(screen.getByTestId('finding-could-not-run')).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Investigate|Promote/ })).toBeNull();
    expect(screen.queryByText('Visual summary')).toBeNull();
    expect(screen.queryByText(/No threat observed/i)).toBeNull();
  });

  it('reads No answer and shows no confidence ring on a hunt that could not answer', async () => {
    vi.mocked(getHunt).mockResolvedValue(
      hunt({
        objective: 'look for traffic to 10.99.0.30',
        kind: 'chat',
        startedBy: 'analyst',
        confidence: 0.75,
        narrative: 'The answer cannot be confirmed or ruled out.',
        outcome: 'no_answer',
        outcome_label: 'No answer',
        outcome_headline: 'The data for 10.99.0.30 is 34 days old. The grid answers 30 days back.',
      }),
    );
    mount();
    expect((await screen.findByTestId('hunt-disposition')).textContent).toBe('No answer');
    expect(screen.getByTestId('hunt-outcome-headline').textContent).toContain('30 days back');
    expect(screen.queryByText('0.75')).toBeNull();
  });

  it('keeps the ring and the Complete chip on a clean hunt', async () => {
    // Negative control: a hunt that tested its objective keeps both.
    vi.mocked(getHunt).mockResolvedValue(
      hunt({
        objective: 'look for beaconing',
        kind: 'chat',
        startedBy: 'analyst',
        confidence: 0.75,
        outcome: 'no_threat',
        outcome_label: 'No threat found',
      }),
    );
    mount();
    expect((await screen.findByTestId('hunt-disposition')).textContent).toBe('No threat found');
    expect(screen.getByText('0.75')).toBeInTheDocument();
    expect(screen.getByText('Complete')).toBeInTheDocument();
    expect(screen.queryByTestId('hunt-outcome-headline')).toBeNull();
  });

  it('derives the outcome from the report when an older server sends none', () => {
    expect(huntOutcome({ status: 'complete', findings: [RUN_FAILURE] })).toBe('could_not_run');
    expect(
      huntOutcome({ status: 'complete', findings: [{ ...RUN_FAILURE, title: 'No DNS logs' }] }),
    ).toBe('no_answer');
    expect(huntOutcome({ status: 'cancelled', findings: [] })).toBe('could_not_run');
    expect(huntOutcome({ status: 'complete', findings: [] })).toBe('no_threat');
    expect(
      huntOutcome({
        status: 'complete',
        findings: [{ ...RUN_FAILURE, category: 'threat', title: 'beacon' }],
      }),
    ).toBe('threat_found');
    // Negative control: a threat titled with the suffix is still a threat.
    expect(isRunFailure({ title: 'x: could not run', category: 'threat' })).toBe(false);
  });
});
