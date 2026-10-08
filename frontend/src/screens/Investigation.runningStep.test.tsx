// A running re-run (dogfood 2026-10-06, first hour W11). The display stayed
// on "4 steps · tool calls 0 · Working…" for minutes with no estimate. It now
// names the step and states how long runs on this grid take. The control: a
// store with too few runs gives the plain range.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { Investigation as Inv } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getChatThread: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  getMe: vi.fn().mockResolvedValue({ username: 'analyst' }),
  getAbout: vi.fn().mockResolvedValue({}),
}));

import { Investigation, runEstimate } from './Investigation';

const inv = (over: Partial<Inv>): Inv =>
  ({
    id: 'INV-1',
    groupId: 'ev-1',
    name: 'Rule',
    kind: 'suricata',
    host: '192.0.2.1',
    ip: '—',
    verdict: 'untriaged',
    conf: 0,
    rationale: '',
    summary: [],
    status: 'investigating',
    elapsedLabel: '0m 40s',
    elapsedSec: 40,
    actions: [],
    timeline: [{ id: 's1', group: 'Prefetch & pivots', title: 'Alert context', time: '00:01', detail: '' }],
    nodes: [],
    edges: [],
    seedChat: [],
    ...over,
  }) as Inv;

describe('a running run', () => {
  it('names the step and states the estimate from the store', () => {
    render(
      <MemoryRouter>
        <Investigation
          inv={inv({
            currentStep: 'the agent searches the events',
            typicalRun: { lowMin: 2, highMin: 5, medianMin: 3, samples: 20 },
          })}
          layout="drawer"
        />
      </MemoryRouter>,
    );
    expect(screen.getByTestId('running-now').textContent).toContain('Now the agent searches the events.');
    expect(screen.getByTestId('running-estimate').textContent).toContain(
      'A run on this grid takes 2 to 5 minutes. The median of the last 20 runs is 3 minutes.',
    );
  });

  it('control: with no store estimate it gives the plain range', () => {
    expect(runEstimate(null)).toBe('A run takes 1 to 5 minutes.');
    expect(runEstimate({ lowMin: 3, highMin: 3, medianMin: 3, samples: 4 })).toBe(
      'A run on this grid takes about 3 minutes. The median of the last 4 runs is 3 minutes.',
    );
  });
});
