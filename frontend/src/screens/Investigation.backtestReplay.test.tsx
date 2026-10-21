// The page of a backtest replay. A replay measures the model on an alert an
// analyst already closed. The page carries a grey "Backtest replay" chip beside
// the verdict, and the server closes every recommended action of a replay, so
// the page offers no Execute button (dogfood 2026-10-06: each replay offered
// "Escalate to case · Execute").
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

const escalate = (over: Partial<RecommendedAction>): RecommendedAction =>
  ({
    id: 'a0',
    title: 'Escalate to case',
    tag: 'escalate',
    rationale: 'Confirmed beacon.',
    applied: false,
    ...over,
  }) as RecommendedAction;

const inv = (ranBy: string, actions: RecommendedAction[]): Inv =>
  ({
    id: 'INV-1',
    groupId: 'ev-1',
    name: 'ET MALWARE beacon',
    kind: 'suricata',
    host: '192.0.2.10',
    ip: '198.51.100.7',
    verdict: 'true_positive',
    conf: 0.9,
    rationale: 'Beacon to a known C2.',
    summary: [{ t: 'text', v: 'Beacon to a known C2.' }],
    status: 'complete',
    elapsedLabel: '1m 5s',
    actions,
    timeline: [],
    nodes: [],
    edges: [],
    seedChat: [],
    meta: { model: 'm', ranBy, ranAt: '2026-07-15T01:00:00+00:00', toolCalls: 3, pivots: 1 },
  }) as Inv;

const mount = (i: Inv) =>
  render(
    <MemoryRouter>
      <Investigation inv={i} layout="page" />
    </MemoryRouter>,
  );

describe('the page of a backtest replay', () => {
  it('shows the chip and no Execute button', () => {
    // The server's shape for a replay: the action is closed with a note.
    mount(
      inv('backtest', [
        escalate({ applied: true, appliedNote: 'Not executable. This run is a backtest replay.' }),
      ]),
    );
    expect(screen.getByTestId('backtest-replay-chip').textContent).toBe('Backtest replay');
    expect(screen.getByText('Escalate to case')).toBeTruthy();
    expect(screen.queryByRole('button', { name: /Execute|Escalate to case|Dismiss/ })).toBeNull();
    expect(screen.getByText(/Not executable\. This run is a backtest replay\./)).toBeTruthy();
  });

  it('control: a live run has no chip and keeps its write button', () => {
    mount(inv('analyst', [escalate({})]));
    expect(screen.queryByTestId('backtest-replay-chip')).toBeNull();
    expect(screen.getByRole('button', { name: /Escalate to case/ })).toBeTruthy();
  });

  it('renders a closed replay action grey, never as a green write', () => {
    mount(
      inv('backtest', [
        escalate({ applied: true, appliedNote: 'Not executable. This run is a backtest replay.' }),
      ]),
    );
    const closed = screen.getByTestId('action-closed');
    expect(closed.className).toContain('text-dim');
    expect(closed.textContent).toBe('Not executable. This run is a backtest replay.');
    expect(screen.queryByTestId('action-record')).toBeNull();
    expect(screen.queryByText(/Executed by/)).toBeNull();
  });

  it('control: a live executed action keeps its green record', () => {
    mount(
      inv('analyst', [
        escalate({ applied: true, appliedBy: 'alice', appliedAt: '2026-07-15T01:00:00+00:00' }),
      ]),
    );
    expect(screen.queryByTestId('action-closed')).toBeNull();
    expect(screen.getByTestId('action-record').textContent).toContain('Executed by alice');
  });

  it('offers no settled bar on a replay', () => {
    mount(inv('backtest', []));
    expect(screen.queryByText('No automatic action')).toBeNull();
    expect(screen.queryByRole('button', { name: /^Acknowledge$/ })).toBeNull();
    expect(screen.queryByRole('button', { name: /Escalate to case/ })).toBeNull();
  });

  it('control: a live run with no actions keeps the settled bar', () => {
    mount(inv('analyst', []));
    expect(screen.getByText('No automatic action')).toBeTruthy();
    expect(screen.getByRole('button', { name: /^Acknowledge$/ })).toBeTruthy();
  });
});
