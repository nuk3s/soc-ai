// Dogfood 2026-10-06 W10: a running hunt showed the elapsed time and a fixed
// sentence. The newest step sat at the bottom of the timeline, below the fold.
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { AboutInfo, HuntDetailData, TimelineStep } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getHunt: vi.fn(),
  getHunts: vi.fn().mockResolvedValue([]),
  getLead: vi.fn(),
  getHuntChat: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  postHuntChat: vi.fn(),
  getAbout: vi.fn(),
}));

import { getAbout, getHunt } from '../lib/api';
import { HuntDetail, runningLine } from './HuntDetail';

const about: AboutInfo = {
  version: '1.0.0',
  repo_url: 'https://example.test/soc-ai',
  license: 'MIT',
  update_check_enabled: false,
  general_chat_enabled: true,
  sigma_authoring_enabled: false,
};

const step = (n: number, group: string, title: string): TimelineStep =>
  ({ id: `h${n}`, group, title, time: '', detail: '' }) as unknown as TimelineStep;

const timeline = [
  step(1, 'Objective', 'Objective'),
  ...Array.from({ length: 8 }, (_, i) =>
    step(i + 2, 'Tool calls', 'Searched for traffic to 10.99.0.30 over 30 days: 0 events'),
  ),
];

function running(over: Partial<HuntDetailData> = {}): HuntDetailData {
  return {
    id: 'H-9',
    objective: 'look for traffic to 10.99.0.30',
    kind: 'chat',
    status: 'running',
    narrative: '',
    findings: [],
    affectedHosts: [],
    mitreTechniques: [],
    recommendedActions: [],
    confidence: null,
    startedBy: 'analyst',
    elapsedLabel: '2m 10s',
    elapsedSec: 130,
    ts: '2026-10-06T00:00:00Z',
    timeline,
    diff: null,
    outcome: 'running',
    currentStep: 'the model reads the results',
    typicalRun: { lowMin: 5, highMin: 8, medianMin: 6, samples: 4 },
    ...over,
  };
}

describe('HuntDetail running line', () => {
  beforeEach(() => {
    vi.clearAllMocks();
    vi.mocked(getAbout).mockResolvedValue(about);
  });

  it('states the step, the typical run and what the hunt does now', async () => {
    vi.mocked(getHunt).mockResolvedValue(running());
    render(
      <MemoryRouter initialEntries={['/hunts/H-9']}>
        <Routes>
          <Route path="/hunts/:id" element={<HuntDetail />} />
        </Routes>
      </MemoryRouter>,
    );
    expect((await screen.findByTestId('hunt-running-line')).textContent).toBe(
      'Step 8 · hunts on this grid take 5 to 8 minutes · now: the model reads the results',
    );
    expect(screen.queryByText(/maps them to MITRE/)).toBeNull();
  });

  it('leaves out a part the server did not send', () => {
    // Negative control: an older server sends no estimate and no step word.
    expect(runningLine(running({ typicalRun: null, currentStep: null }))).toBe('Step 8');
    expect(
      runningLine(running({ typicalRun: { lowMin: 6, highMin: 6, medianMin: 6, samples: 3 } })),
    ).toBe('Step 8 · hunts on this grid take about 6 minutes · now: the model reads the results');
  });
});
