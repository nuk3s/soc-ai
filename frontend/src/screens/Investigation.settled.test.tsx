// A pipeline-fallback run failed BEFORE reaching a verdict — the red panel says
// "re-run it to get a real verdict". Rendering "VERDICT SETTLED — TAKE ACTION"
// (ack/escalate) directly under it contradicts that guidance (dogfood
// 2026-07-15): there is no settled verdict to act on.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { Investigation as Inv } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getChatThread: vi.fn().mockResolvedValue({ messages: [], pending: false }),
}));

import { Investigation } from './Investigation';

const baseInv = (over: Partial<Inv>): Inv =>
  ({
    id: 'INV-1',
    groupId: 'ev-1',
    name: 'GPL ICMP Large ICMP Packet',
    kind: 'suricata',
    host: '192.0.2.10',
    ip: '198.51.100.7',
    verdict: 'needs_more_info',
    conf: 0.3,
    rationale: 'pipeline fallback',
    summary: [{ t: 'text', v: 'fallback' }],
    status: 'complete',
    elapsedLabel: '4m 5s',
    actions: [],
    timeline: [],
    nodes: [],
    edges: [],
    seedChat: [],
    ...over,
  }) as Inv;

describe('settled-action bar vs pipeline fallback', () => {
  it('suppresses the settled bar on a fallback run', () => {
    render(
      <MemoryRouter>
        <Investigation
          inv={baseInv({ fallback: { provenance: 'pipeline_fallback' } })}
          layout="page"
        />
      </MemoryRouter>,
    );
    expect(screen.queryByText(/Verdict settled — take action/i)).toBeNull();
    expect(screen.getByText(/failed before reaching a verdict/i)).toBeTruthy();
  });

  it('keeps the settled bar on a genuine actionless complete run', () => {
    render(
      <MemoryRouter>
        <Investigation inv={baseInv({ fallback: null })} layout="page" />
      </MemoryRouter>,
    );
    expect(screen.getByText(/Verdict settled — take action/i)).toBeTruthy();
  });
});
