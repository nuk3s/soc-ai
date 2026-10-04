// RL3 (dogfood 2026-10-01): the panel "Host context <source ip>" listed the
// destination's alerts, because the list pooled both ends of the alert. The
// page now shows one panel per end, each named, and a run stored before the
// split says that its one list covers both ends.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { Investigation as Inv } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getChatThread: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  getMe: vi.fn().mockResolvedValue({ username: 'analyst' }),
}));

import { Investigation } from './Investigation';

const sig = (label: string) => ({ time: '', label, tone: 'low' as const, w: 50, sev: '2×' });

const baseInv = (over: Partial<Inv>): Inv =>
  ({
    id: 'INV-1',
    groupId: 'ev-1',
    name: 'ET INFO NTLM Session Setup Request',
    kind: 'suricata',
    host: '192.0.2.20',
    ip: '192.0.2.40',
    verdict: 'false_positive',
    conf: 0.7,
    rationale: 'benign',
    summary: [{ t: 'text', v: 'benign' }],
    status: 'complete',
    elapsedLabel: '1m',
    actions: [],
    timeline: [],
    nodes: [],
    edges: [],
    seedChat: [],
    ...over,
  }) as Inv;

describe('host context panels', () => {
  it('names each end of the alert in its own panel', () => {
    render(
      <MemoryRouter>
        <Investigation
          layout="page"
          inv={baseInv({
            hostContext: [sig('ET SCAN probe'), sig('ET POLICY fetch')],
            hostContexts: [
              { ip: '192.0.2.20', end: 'source', asSource: [sig('ET POLICY fetch')], asDestination: [] },
              { ip: '192.0.2.40', end: 'destination', asSource: [], asDestination: [sig('ET SCAN probe')] },
            ],
          })}
        />
      </MemoryRouter>,
    );
    // Each panel header names its host and which end of the alert it is.
    const headers = screen
      .getAllByRole('button', { name: /^Host context/ })
      .map((b) => b.textContent?.replace(/\s+/g, ' ').trim());
    expect(headers).toEqual(['Host contextsource192.0.2.20', 'Host contextdestination192.0.2.40']);
    // The destination's alert sits under the destination's own list only.
    expect(screen.getAllByText('ET SCAN probe')).toHaveLength(1);
    expect(screen.getByText('Alerts with this host as source')).toBeTruthy();
    expect(screen.queryByText('Both ends')).toBeNull();
  });

  it('labels a pooled list from an older run as covering both ends', () => {
    render(
      <MemoryRouter>
        <Investigation layout="page" inv={baseInv({ hostContext: [sig('ET SCAN probe')] })} />
      </MemoryRouter>,
    );
    expect(screen.getByText('Both ends')).toBeTruthy();
    expect(screen.getByText('Alerts on either end of this alert')).toBeTruthy();
  });
});
