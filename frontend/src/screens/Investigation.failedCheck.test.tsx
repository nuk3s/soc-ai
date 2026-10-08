// A failed tool call in the timeline (dogfood 2026-10-06, W4). The raw error
// "Event search: failed: unknown or forbidden field" leaked into the
// timeline. It now folds as "A follow-up check could not run" with the error
// behind the toggle. The negative control: a tool call that worked keeps its
// title.
import { fireEvent, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { Investigation as Inv } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getChatThread: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  getMe: vi.fn().mockResolvedValue({ username: 'analyst' }),
  getAbout: vi.fn().mockResolvedValue({}),
}));

import { Investigation, failedToolStep } from './Investigation';

const RAW = "Event search: failed: unknown or forbidden field: 'system.auth.ssh.event'";

const inv = {
  id: 'INV-1',
  groupId: 'ev-1',
  name: 'SSH',
  kind: 'suricata',
  host: '192.0.2.1',
  ip: '—',
  verdict: 'false_positive',
  conf: 0.7,
  rationale: 'Benign.',
  summary: [{ t: 'text', v: 'x' }],
  status: 'complete',
  elapsedLabel: '1m',
  actions: [],
  timeline: [
    { id: 's1', group: 'Tool calls', title: RAW, time: '00:01', detail: 'query: {"q":"x"}' },
    { id: 's2', group: 'Tool calls', title: 'Event search: 4 events', time: '00:02', detail: 'result: 4' },
  ],
  nodes: [],
  edges: [],
  seedChat: [],
} as unknown as Inv;

describe('a failed tool call', () => {
  it('folds as a check that could not run, with the error behind the toggle', () => {
    render(
      <MemoryRouter>
        <Investigation inv={inv} layout="page" />
      </MemoryRouter>,
    );
    expect(screen.getByTestId('failed-check').textContent).toBe('A follow-up check could not run');
    expect(screen.queryByText(RAW)).toBeNull();
    fireEvent.click(screen.getByText('Show the error'));
    expect(screen.getByText(/unknown or forbidden field/)).toBeTruthy();
    // Negative control: the call that worked keeps its title.
    expect(screen.getByText('Event search: 4 events')).toBeTruthy();
  });

  it('reads only a failed tool call as failed', () => {
    expect(failedToolStep({ group: 'Tool calls', title: RAW })).toEqual({ tool: 'Event search' });
    expect(failedToolStep({ group: 'Tool calls', title: 'Prevalence: rare' })).toBeNull();
    expect(failedToolStep({ group: 'Validators', title: 'Citations: failed: 1' })).toBeNull();
  });
});

// Dogfood 2026-10-06, first hour C2: the timeline groups read as build terms.
describe('the timeline group labels', () => {
  it('read in analyst words', () => {
    render(
      <MemoryRouter>
        <Investigation
          inv={{
            ...inv,
            timeline: [
              { id: 'p', group: 'Prefetch & pivots', title: 'Alert context', time: '', detail: '' },
              { id: 'v', group: 'Validators', title: 'Citations resolve', time: '', detail: '' },
            ],
          }}
          layout="page"
        />
      </MemoryRouter>,
    );
    const labels = screen.getAllByTestId('timeline-group').map((n) => n.textContent);
    expect(labels).toEqual(['Context gathered', 'Checks']);
    // Negative control: no build term is on screen.
    expect(screen.queryByText('Prefetch & pivots')).toBeNull();
    expect(screen.queryByText('Validators')).toBeNull();
  });
});
