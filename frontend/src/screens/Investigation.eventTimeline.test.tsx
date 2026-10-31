// The investigation page shows the Event timeline above the step timeline
// (change D): the documents of the run in event time, in UTC, with the waves.
// Every time here is an offset from Date.now().
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { EventTimeline, Investigation as Inv } from '../lib/types';

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getChatThread: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  getMe: vi.fn().mockResolvedValue({ username: 'analyst' }),
}));

import { Investigation } from './Investigation';

const BASE = Math.floor((Date.now() - 4 * 86_400_000) / 1000) * 1000;
const iso = (ms: number) => new Date(ms).toISOString();

const EVENT_TIMELINE: EventTimeline = {
  basis: 'hunt_subject',
  gapMinutes: 30,
  untimed: 0,
  omitted: 0,
  entries: [
    {
      id: 'docConn00000001',
      at: iso(BASE),
      end: iso(BASE + 3_000_000),
      dataset: 'zeek.conn',
      source: '192.0.2.10',
      destination: '198.51.100.20:22',
      host: null,
      label: 'Connection, state SF',
      cited: true,
      findings: [],
      wave: 1,
    },
    {
      id: 'docAlert0000001',
      at: iso(BASE + 80_000_000),
      end: null,
      dataset: 'suricata.alert',
      source: '192.0.2.11',
      destination: '198.51.100.20',
      host: null,
      label: 'ET EXPLOIT Example upload attempt',
      cited: true,
      findings: [],
      wave: 2,
    },
  ],
  waves: [
    {
      n: 1,
      start: iso(BASE),
      end: iso(BASE + 3_000_000),
      documents: 1,
      sources: ['192.0.2.10'],
      destinations: ['198.51.100.20'],
    },
    {
      n: 2,
      start: iso(BASE + 80_000_000),
      end: iso(BASE + 80_000_000),
      documents: 1,
      sources: ['192.0.2.11'],
      destinations: ['198.51.100.20'],
    },
  ],
};

const inv = (over: Partial<Inv> = {}): Inv =>
  ({
    id: 'INV-EVENTS',
    groupId: 'ev-events',
    name: 'ET EXPLOIT Example upload attempt',
    kind: 'suricata',
    host: '192.0.2.11',
    ip: '198.51.100.20',
    verdict: 'true_positive',
    conf: 0.8,
    rationale: 'The upload ran.',
    summary: [{ t: 'text', v: 'The upload ran.' }],
    status: 'complete',
    elapsedLabel: '2m 0s',
    actions: [],
    timeline: [
      { id: 's1', group: 'Tool calls', title: 'Event search', detail: '', time: '' },
    ],
    nodes: [],
    edges: [],
    seedChat: [],
    eventTimeline: EVENT_TIMELINE,
    ...over,
  }) as Inv;

function mount(layout: 'page' | 'drawer', over: Partial<Inv> = {}) {
  return render(
    <MemoryRouter>
      <Investigation inv={inv(over)} layout={layout} />
    </MemoryRouter>,
  );
}

describe('the Event timeline section', () => {
  it.each(['page', 'drawer'] as const)('sits above the step timeline on the %s', (layout) => {
    mount(layout);
    const events = screen.getByText('Event timeline');
    const steps = screen.getByText('Investigation timeline');
    expect(events.compareDocumentPosition(steps) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(screen.getByText('2 documents · 2 waves · UTC')).toBeTruthy();
    expect(screen.getByText(/the documents that soc-ai loaded for this investigation and the documents that the verdict cites/)).toBeTruthy();
  });

  it('is absent when the run holds no event timeline', () => {
    const { unmount } = mount('page', { eventTimeline: null });
    expect(screen.queryByText('Event timeline')).toBeNull();
    unmount();
    mount('page', { eventTimeline: undefined });
    expect(screen.queryByText('Event timeline')).toBeNull();
  });

  it('is absent on a failed run', () => {
    mount('page', { status: 'error', verdict: 'untriaged', conf: 0 });
    expect(screen.queryByText('Event timeline')).toBeNull();
  });
});
