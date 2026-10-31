// The hunt page shows the Event timeline between the findings and the step
// timeline (change D): the documents the findings cite, in event time, in
// UTC, with a chip for each finding that cites a document. The step clock of
// the Hunt timeline is labelled UTC. Every time is an offset from Date.now().
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { EventTimeline, HuntDetailData } from '../lib/types';

const HOUR = 3_600_000;
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();

const EVENT_TIMELINE: EventTimeline = {
  basis: 'hunt',
  gapMinutes: 30,
  untimed: 1,
  omitted: 0,
  entries: [
    {
      id: 'doc-0001-first',
      at: iso(30 * HOUR),
      end: null,
      dataset: 'zeek.conn',
      source: '192.0.2.10',
      destination: '203.0.113.5:443',
      host: null,
      label: 'Connection, state SF',
      cited: true,
      findings: [0, 2],
      wave: 1,
    },
    {
      id: 'doc-0002-later',
      at: iso(3 * HOUR),
      end: null,
      dataset: 'zeek.http',
      source: '192.0.2.10',
      destination: '203.0.113.5',
      host: null,
      label: 'GET /beacon, status 200',
      cited: true,
      findings: [1],
      wave: 2,
    },
  ],
  waves: [
    {
      n: 1,
      start: iso(30 * HOUR),
      end: iso(30 * HOUR),
      documents: 1,
      sources: ['192.0.2.10'],
      destinations: ['203.0.113.5'],
    },
    {
      n: 2,
      start: iso(3 * HOUR),
      end: iso(3 * HOUR),
      documents: 1,
      sources: ['192.0.2.10'],
      destinations: ['203.0.113.5'],
    },
  ],
};

const finding = (title: string) => ({
  title,
  detail: 'The host sent 40 connections at a fixed interval to 203.0.113.5.',
  severity: 'high',
  category: 'threat',
  hosts: ['192.0.2.10'],
  citations: ['doc-0001-first'],
});

const HUNT: HuntDetailData = {
  id: 'H-9',
  objective: 'Hunt for beacons from 192.0.2.10',
  kind: 'chat',
  status: 'complete',
  narrative: 'The host beaconed to one rare external address.',
  findings: [finding('Beacon one'), finding('Beacon two'), finding('Beacon three')],
  affectedHosts: ['192.0.2.10'],
  mitreTechniques: [],
  recommendedActions: [],
  confidence: 0.7,
  startedBy: 'analyst',
  elapsedLabel: '6m 0s',
  elapsedSec: 360,
  ts: iso(2 * HOUR),
  timeline: [
    {
      id: 's1',
      group: 'Tool calls',
      title: 'Search the connection logs of 192.0.2.10',
      time: '00:01',
      detail: 'query_events_oql(192.0.2.10)',
    },
  ],
  diff: null,
  outcome: 'threat_found',
  outcome_label: 'Threat found',
  eventTimeline: EVENT_TIMELINE,
};

const getHunt = vi.hoisted(() => vi.fn());

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getHunt,
  getHunts: vi.fn().mockResolvedValue([]),
  getHuntChat: vi.fn().mockResolvedValue({ messages: [], pending: false }),
}));

import { HuntDetail } from './HuntDetail';

function mount() {
  return render(
    <MemoryRouter initialEntries={['/hunts/H-9']}>
      <Routes>
        <Route path="/hunts/:id" element={<HuntDetail />} />
      </Routes>
    </MemoryRouter>,
  );
}

beforeEach(() => {
  getHunt.mockReset().mockResolvedValue(HUNT);
});

describe('the hunt Event timeline section', () => {
  it('sits after the findings and before the Hunt timeline, with the finding chips', async () => {
    mount();
    const events = await screen.findByText('Event timeline');
    const findings = screen.getByText('Findings');
    const steps = screen.getByText('Hunt timeline');
    expect(findings.compareDocumentPosition(events) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(events.compareDocumentPosition(steps) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    const section = events.closest('[data-tour="hunt-event-timeline"]') as HTMLElement;
    expect(section).toBeTruthy();
    expect(within(section).getByText('F1').getAttribute('title')).toBe('Finding 1 cites this document.');
    expect(within(section).getByText('F3')).toBeTruthy();
    expect(within(section).getByText('F2')).toBeTruthy();
    expect(within(section).getByText('2 documents · 2 waves · UTC')).toBeTruthy();
  });

  it('labels the step clock of the Hunt timeline', async () => {
    mount();
    expect(await screen.findByText(/step times in UTC$/)).toBeTruthy();
    expect(screen.getByText('1 step · 6m 0s · step times in UTC')).toBeTruthy();
  });

  it('is absent on a catalog hunt with no event timeline', async () => {
    getHunt.mockResolvedValue({
      ...HUNT,
      kind: 'triggered',
      startedBy: 'hunt-catalog',
      timeline: [],
      eventTimeline: null,
    });
    mount();
    await screen.findByText('Hunt timeline');
    expect(screen.queryByText('Event timeline')).toBeNull();
    expect(screen.getByText('single query · 6m 0s')).toBeTruthy();
    expect(screen.queryByText(/step times in UTC/)).toBeNull();
  });
});
