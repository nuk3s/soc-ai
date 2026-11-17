// A clear from Needs you on the page of an investigation. The page states the
// one line of the server and keeps the verdict of the run. The control: an
// investigation with no clear shows no line.
import { cleanup, render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Investigation as Inv } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getChatThread: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  getMe: vi.fn().mockResolvedValue({ username: 'analyst' }),
  getAbout: vi.fn().mockResolvedValue({}),
  getActionScope: vi.fn().mockResolvedValue(null),
}));

import { Investigation } from './Investigation';

const LINE = 'Cleared from Needs you on 2026-11-16 by casey: Old work from before the new rules.';

const inv = (over: Partial<Inv> = {}): Inv =>
  ({
    id: 'INV-7',
    groupId: 'ev-7',
    name: 'ET POLICY Example rule',
    kind: 'suricata',
    host: '10.20.30.5',
    ip: '10.40.50.7',
    verdict: 'needs_more_info',
    conf: 0.5,
    rationale: 'The evidence does not decide the verdict.',
    summary: [{ t: 'text', v: 'The evidence does not decide the verdict.' }],
    status: 'complete',
    elapsedLabel: '1m',
    actions: [],
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

afterEach(cleanup);

describe('a clear from Needs you', () => {
  it('states the line of the server', () => {
    mount(inv({ needsYouCleared: LINE }));
    expect(screen.getByTestId('needs-you-cleared').textContent).toBe(LINE);
  });

  it('shows no line on an investigation with no clear', () => {
    mount(inv({ needsYouCleared: null }));
    expect(screen.queryByTestId('needs-you-cleared')).toBeNull();
  });
});
