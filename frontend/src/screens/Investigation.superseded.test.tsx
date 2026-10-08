// A run a newer run replaced (dogfood 2026-10-06, investigation S1).
// "Request more info" started a new run that reached true positive 0.65 on
// the same alert, and the older page kept its needs more info verdict and its
// live buttons. The page now names the newer run and its verdict, links it,
// and turns its actions off. The control: the newest run keeps its buttons.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { Investigation as Inv } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getChatThread: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  getMe: vi.fn().mockResolvedValue({ username: 'analyst' }),
  getAbout: vi.fn().mockResolvedValue({}),
  getActionScope: vi.fn().mockResolvedValue(null),
}));

import { Investigation, supersededSentence } from './Investigation';

const inv = (over: Partial<Inv> = {}): Inv =>
  ({
    id: 'INV-OLD',
    groupId: 'ev-1',
    name: 'SSH scan',
    kind: 'suricata',
    host: '192.0.2.1',
    ip: '—',
    verdict: 'needs_more_info',
    conf: 0.5,
    rationale: 'The model needs the auth log.',
    summary: [{ t: 'text', v: 'x' }],
    status: 'complete',
    elapsedLabel: '1m',
    actions: [{ id: 'a0', title: 'Escalate to case', tag: 'escalate', rationale: 'r' }],
    timeline: [],
    nodes: [],
    edges: [],
    seedChat: [],
    ...over,
  }) as Inv;

const mount = (i: Inv) =>
  render(
    <MemoryRouter>
      <Investigation inv={i} layout="page" />
    </MemoryRouter>,
  );

describe('a run a newer run replaced', () => {
  it('names the newer verdict, links it and turns the actions off', () => {
    mount(
      inv({
        supersededBy: 'INV-NEW',
        supersededRun: { id: 'INV-NEW', status: 'complete', verdict: 'true_positive', conf: 0.65 },
      }),
    );
    const banner = screen.getByTestId('superseded-banner');
    expect(banner.textContent).toContain('A newer run on this alert reached true positive (0.65).');
    expect(screen.getByRole('link', { name: 'Open it.' }).getAttribute('href')).toBe(
      '/investigation/INV-NEW',
    );
    expect(screen.getByRole('button', { name: /Escalate to case/ })).toBeDisabled();
    expect(screen.getByRole('button', { name: /Dismiss/ })).toBeDisabled();
    expect(screen.getByRole('button', { name: /Request more info/ })).toBeDisabled();
  });

  it('control: the newest run has no banner and keeps its buttons', () => {
    mount(inv());
    expect(screen.queryByTestId('superseded-banner')).toBeNull();
    expect(screen.getByRole('button', { name: /Escalate to case/ })).not.toBeDisabled();
    expect(screen.getByRole('button', { name: /Request more info/ })).not.toBeDisabled();
  });

  it('says a newer run is in progress while it runs', () => {
    expect(supersededSentence({ id: 'x', status: 'running' })).toBe(
      'A newer run on this alert is in progress.',
    );
    expect(supersededSentence(null)).toBe('A newer run on this alert replaced this run.');
  });
});
