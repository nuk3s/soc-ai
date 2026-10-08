// Every executed action names who or what executed it, and when (dogfood
// 2026-10-06, investigation S3). The card read "Executed · anonymous" for an
// ack the analyst never clicked, with no time, while the grid said the alert
// was not acknowledged.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { Investigation as Inv, RecommendedAction } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getChatThread: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  getMe: vi.fn().mockResolvedValue({ username: 'analyst' }),
  getAbout: vi.fn().mockResolvedValue({}),
  getActionScope: vi.fn().mockResolvedValue(null),
}));

import { Investigation } from './Investigation';
import { clockTime, executedLine } from '../components/ActionCard';

const inv = (actions: RecommendedAction[]): Inv =>
  ({
    id: 'INV-1',
    groupId: 'ev-1',
    name: 'Rule',
    kind: 'suricata',
    host: '192.0.2.1',
    ip: '—',
    verdict: 'false_positive',
    conf: 0.9,
    rationale: 'Benign.',
    summary: [{ t: 'text', v: 'benign' }],
    status: 'complete',
    elapsedLabel: '1m',
    actions,
    timeline: [],
    nodes: [],
    edges: [],
    seedChat: [],
  }) as Inv;

const mount = (actions: RecommendedAction[]) =>
  render(
    <MemoryRouter>
      <Investigation inv={inv(actions)} layout="page" />
    </MemoryRouter>,
  );

const AT = '2026-10-06T03:12:00+00:00';

describe('the executed action record', () => {
  it('formats the actor and the local clock time', () => {
    expect(executedLine('auto-ack', AT)).toBe(`Executed by auto-ack at ${clockTime(AT)}`);
    expect(clockTime(AT)).toMatch(/^\d{2}:\d{2}$/);
    // Negative control: no time, no "at".
    expect(executedLine('alice', null)).toBe('Executed by alice');
    expect(clockTime('not a time')).toBeNull();
  });

  it('names auto-ack and its time on an auto-acknowledged card', () => {
    mount([
      { id: 'a0', title: 'Acknowledge alert', tag: 'ack', rationale: 'benign', applied: true,
        appliedBy: 'auto-ack', appliedAt: AT },
    ]);
    expect(screen.getByTestId('action-record').textContent).toBe(
      `✓ Executed by auto-ack at ${clockTime(AT)}`,
    );
  });

  it('names the user who executed it', () => {
    mount([
      { id: 'a0', title: 'Escalate to case', tag: 'escalate', rationale: 'r', applied: true,
        appliedBy: 'alice', appliedAt: AT, appliedDetail: 'soc-ai created case 7.' },
    ]);
    expect(screen.getByTestId('action-record').textContent).toContain('Executed by alice at');
    expect(screen.getByText('soc-ai created case 7.')).toBeTruthy();
  });

  it('does not say executed for an ack the grid shows unacknowledged', () => {
    mount([
      { id: 'a0', title: 'Acknowledge alert', tag: 'ack', rationale: 'r', applied: false,
        appliedBy: 'anonymous', appliedAt: AT,
        pendingNote: 'Security Onion shows this alert as not acknowledged.' },
    ]);
    expect(screen.queryByTestId('action-record')).toBeNull();
    expect(screen.getByText('Security Onion shows this alert as not acknowledged.')).toBeTruthy();
    expect(screen.getByTestId('action-earlier-write').textContent).toContain('by anonymous at');
  });
});
