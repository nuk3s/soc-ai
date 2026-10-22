// The lead page tour: every anchor the tour names is on the page with data.
//
// The lead is hunted, its hunt is on record, and the investigation of a hunt
// finding reached a verdict, so the promotion strip shows.
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import { describe, expect, it, vi } from 'vitest';

const HOUR = 3_600_000;
const iso = (msAgo: number) => new Date(Date.now() - msAgo).toISOString();

const LEAD = {
  id: 7,
  status: 'hunting',
  formed_at: iso(5 * HOUR),
  updated_at: null,
  entities: [['host', '192.0.2.10']],
  kinds: ['catalog_match', 'off_hours'],
  weight_at_formation: 1.0,
  weight_now: 0.9,
  scope_count: 1,
  hunt_id: 'H-7',
  hunt_status: 'complete',
  hunt_outcome: 'threats',
  hunt_outcome_label: 'Threat findings',
  shadow: false,
  single_signal: false,
  dismissed_reason: null,
  dismissed_note: null,
  dismissed_by: null,
  dismissed_at: null,
  investigation_id: null,
  dismiss_reasons: ['expected_for_role', 'other'],
  decisions: [],
  observations: [
    {
      id: 1,
      kind: 'catalog_match',
      spec_id: 'local-http-service-executes-id-command',
      summary: 'HTTP service executes id command: 192.0.2.10 (2 documents)',
      occurrences: 1,
      born_at: iso(5 * HOUR),
      first_seen_at: iso(5 * HOUR),
      source: 'catalog',
      shadow: false,
      weight_now: 0.9,
      birth_weight: 1.0,
      evidence: { sample_ids: ['doc-0001'] },
    },
  ],
  hunts: [
    {
      id: 'H-7',
      status: 'complete',
      outcome: 'threats',
      outcome_label: 'Threat findings',
      threat_findings: 1,
      steps: 12,
      elapsed_sec: 360,
      started_at: iso(4 * HOUR),
      started_by: 'analyst',
      answer: 'The service ran the id command for a remote client.',
      not_checked: [],
    },
  ],
  promoted_findings: [
    {
      investigation_id: '01INV0000000000000000000000',
      hunt_id: 'H-7',
      finding_ordinal: 0,
      finding_title: 'HTTP service executes id command as root',
      promoted_by: 'analyst',
      promoted_at: iso(3 * HOUR),
      status: 'complete',
      verdict: 'true_positive',
      confidence: 0.75,
    },
  ],
};

vi.mock('../lib/api', async () => {
  const actual = await vi.importActual<typeof import('../lib/api')>('../lib/api');
  return {
    ...actual,
    getLead: vi.fn(async () => LEAD),
    getHunt: vi.fn().mockRejectedValue(new Error('offline')),
    getNeedsYou: vi.fn().mockResolvedValue({
      unread_shadow_hits: 0,
      leads_needing_decision: 1,
      total: 1,
      lead_auto_hunt: false,
    }),
    listMachines: vi.fn().mockResolvedValue({ rows: [], total: 0 }),
    getEvent: vi.fn(),
  };
});

import { LEAD_TOUR } from '../tours/content';
import { missingAnchors } from '../tours/testing';
import { ShellProvider } from '../shell/ShellContext';
import { LeadDetail } from './LeadDetail';

describe('the lead page tour', () => {
  it('finds every anchor it names on the page', async () => {
    render(
      <MemoryRouter initialEntries={['/leads/7']}>
        <ShellProvider>
          <Routes>
            <Route path="/leads/:id" element={<LeadDetail />} />
          </Routes>
        </ShellProvider>
      </MemoryRouter>,
    );
    await screen.findByTestId('lead-verdict-strip');
    await screen.findByTestId('lead-hunts');
    expect(missingAnchors(LEAD_TOUR)).toEqual([]);
  });
});
