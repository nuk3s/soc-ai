// The hunt page tour: every anchor the tour names is on the page with data.
//
// The hunt is a complete lead hunt whose lead is still open, so the lead
// decision bar shows. One finding cites a host and a document, so the
// evidence row shows. The timeline holds one step. Two timed documents put
// the Event timeline on the page.
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';
import type { AboutInfo, HuntDetailData } from '../lib/types';

const HOUR = 3_600_000;
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();

const ABOUT: AboutInfo = {
  version: '1.0.0',
  repo_url: 'https://example.test/soc-ai',
  license: 'MIT',
  update_check_enabled: false,
  general_chat_enabled: true,
  sigma_authoring_enabled: false,
};

const HUNT: HuntDetailData = {
  id: 'H-7',
  objective: '[lead 7] Investigate 192.0.2.10. The lead formed from two types.',
  kind: 'lead',
  status: 'complete',
  narrative: 'The host reached one rare external address outside its usual hours.',
  findings: [
    {
      title: 'Beacon to a rare external address',
      detail: 'The host sent 40 connections at a fixed interval to 203.0.113.5.',
      severity: 'high',
      category: 'threat',
      hosts: ['192.0.2.10'],
      citations: ['doc-0001'],
    },
  ],
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
  leadId: 7,
  outcome: 'threat_found',
  outcome_label: 'Threat found',
  // Two timed documents, so the Event timeline section is on the page.
  eventTimeline: {
    basis: 'hunt',
    gapMinutes: 30,
    untimed: 0,
    omitted: 0,
    entries: [
      {
        id: 'doc-0001',
        at: iso(4 * HOUR),
        end: null,
        dataset: 'zeek.conn',
        source: '192.0.2.10',
        destination: '203.0.113.5',
        host: null,
        label: 'Connection, state SF',
        cited: true,
        findings: [0],
        wave: 1,
      },
      {
        id: 'doc-0002',
        at: iso(3 * HOUR),
        end: null,
        dataset: 'zeek.conn',
        source: '192.0.2.10',
        destination: '203.0.113.5',
        host: null,
        label: 'Connection, state SF',
        cited: true,
        findings: [0],
        wave: 2,
      },
    ],
    waves: [
      {
        n: 1,
        start: iso(4 * HOUR),
        end: iso(4 * HOUR),
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
  },
};

const LEAD = {
  id: 7,
  status: 'open',
  formed_at: iso(3 * HOUR),
  updated_at: iso(3 * HOUR),
  entities: [['host', '192.0.2.10']],
  kinds: ['novel_destination', 'off_hours'],
  weight_at_formation: 0.9,
  weight_now: 0.9,
  hunt_id: 'H-7',
  single_signal: false,
  dismissed_reason: null,
  dismissed_note: null,
  dismissed_by: null,
  dismissed_at: null,
  investigation_id: null,
  dismiss_reasons: ['expected_for_role', 'other'],
  observations: [],
};

vi.mock('../lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('../lib/api')>()),
  getHunt: vi.fn(async () => HUNT),
  getHunts: vi.fn().mockResolvedValue([]),
  getLead: vi.fn(async () => LEAD),
  getHuntChat: vi.fn().mockResolvedValue({ messages: [], pending: false }),
  getAbout: vi.fn(async () => ABOUT),
}));

import { HUNT_TOUR } from '../tours/content';
import { missingAnchors } from '../tours/testing';
import { HuntDetail } from './HuntDetail';

describe('the hunt page tour', () => {
  it('finds every anchor it names on the page', async () => {
    render(
      <MemoryRouter initialEntries={['/hunts/H-7']}>
        <Routes>
          <Route path="/hunts/:id" element={<HuntDetail />} />
        </Routes>
      </MemoryRouter>,
    );
    await screen.findByTestId('hunt-title');
    await screen.findByTestId('hunt-lead-decision');
    expect(missingAnchors(HUNT_TOUR)).toEqual([]);
  });
});
