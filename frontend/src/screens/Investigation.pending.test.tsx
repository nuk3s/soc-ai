// (1) The RECOMMENDED ACTIONS header must not count an action the system already
//     carried out (auto-ack). A completed FP run with a single applied action
//     used to read "1 pending" while the only card said "✓ Auto-acknowledged".
// (2) Opening chat on a message-less investigation shows a starter hint with
//     suggested questions instead of a blank void.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { Investigation as Inv, RecommendedAction } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getChatThread: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  getMe: vi.fn().mockResolvedValue({ username: 'analyst' }),
}));

import { Investigation } from './Investigation';

const baseInv = (over: Partial<Inv>): Inv =>
  ({
    id: 'INV-1',
    groupId: 'ev-1',
    name: 'ET INFO Suspicious Beacon',
    kind: 'suricata',
    host: '192.0.2.10',
    ip: '198.51.100.7',
    verdict: 'false_positive',
    conf: 0.92,
    rationale: 'benign scanner',
    summary: [{ t: 'text', v: 'benign' }],
    status: 'complete',
    elapsedLabel: '1m 2s',
    actions: [],
    timeline: [],
    nodes: [],
    edges: [],
    seedChat: [],
    ...over,
  }) as Inv;

const appliedAction: RecommendedAction = {
  id: 'a1',
  title: 'Acknowledge detection',
  tag: 'ack',
  rationale: 'auto-ack: benign',
  applied: true,
  appliedNote: null,
};

describe('recommended-actions pending count', () => {
  it('excludes an already auto-acked action from the pending count', () => {
    render(
      <MemoryRouter>
        <Investigation inv={baseInv({ actions: [appliedAction] })} layout="page" />
      </MemoryRouter>,
    );
    // header meta: "human-in-the-loop · 0 pending"
    expect(screen.getByText(/0 pending/)).toBeTruthy();
    expect(screen.queryByText(/1 pending/)).toBeNull();
  });

  it('still counts a genuinely un-executed action', () => {
    render(
      <MemoryRouter>
        <Investigation
          inv={baseInv({ actions: [{ ...appliedAction, applied: false }] })}
          layout="page"
        />
      </MemoryRouter>,
    );
    expect(screen.getByText(/1 pending/)).toBeTruthy();
  });
});

describe('empty investigation chat', () => {
  it('renders suggested starter questions when the thread is empty', () => {
    render(
      <MemoryRouter>
        <Investigation inv={baseInv({ seedChat: [] })} layout="drawer" />
      </MemoryRouter>,
    );
    expect(screen.getByText('Why not a false positive?')).toBeTruthy();
    expect(screen.getByText(/Ask a follow-up about this investigation/i)).toBeTruthy();
  });
});
