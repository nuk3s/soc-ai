// A benign observation on the lead page (2026-10-19).
//
// The grid-gap review marks the hits of a gap benign, and one of them sat on
// lead 5 of the range. A benign observation counts toward no lead, so the
// server reads its weight as 0. The row says why, or the 0 reads as a fault.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import { ShellProvider } from '../shell/ShellContext';
import { LeadTimeline } from './LeadTimeline';
import { GRID_GAP_REASON, benignLine } from './LeadsStrip';

const NOTE = 'Grid gap from 2026-10-15 13:36 UTC to 2026-10-19 10:15 UTC';

const OBS = {
  kind: 'below_baseline',
  spec_id: 'profile-connection-rate-collapsed',
  summary: 'The connection rate on Sunday 16:00 is 0 per hour.',
  occurrences: 1,
  first_seen_at: null,
  source: 'profile',
  shadow: false,
  birth_weight: 0.5,
  analytic_exists: true,
  observed_at: null,
  evidence: { window: { start: '2026-10-18T11:00:00Z', end: '2026-10-19T10:00:00Z' } },
};

const LEAD = {
  id: 5,
  status: 'open',
  formed_at: '2026-10-19T10:21:00Z',
  updated_at: null,
  entities: [['host', '192.0.2.10']],
  kinds: ['below_baseline'],
  weight_at_formation: 1,
  weight_now: 0.4,
  scope_count: 1,
  hunt_id: null,
  shadow: false,
  single_signal: false,
  dismissed_reason: null,
  dismissed_note: null,
  dismissed_by: null,
  dismissed_at: null,
  investigation_id: null,
  dismiss_reasons: [],
  decisions: [],
  promoted_findings: [],
  observations: [
    {
      ...OBS,
      id: 89,
      born_at: '2026-10-19T10:21:38Z',
      weight_now: 0,
      dismissed_reason: GRID_GAP_REASON,
      dismissed_note: NOTE,
      dismissed_by: 'jordan',
      dismissed_at: '2026-10-19T12:00:00Z',
    },
    { ...OBS, id: 90, born_at: '2026-10-19T10:21:38Z', weight_now: 0.4 },
  ],
};

describe('benignLine', () => {
  it('states the note of a grid-gap mark', () => {
    expect(
      benignLine({ dismissed_by: 'jordan', dismissed_reason: GRID_GAP_REASON, dismissed_note: NOTE }),
    ).toBe(`Marked benign by jordan: ${NOTE}. It counts toward no lead.`);
  });

  it('states the label of an analyst reason', () => {
    expect(benignLine({ dismissed_by: 'alice', dismissed_reason: 'known_change' })).toBe(
      'Marked benign by alice: A known change. It counts toward no lead.',
    );
  });
});

describe('LeadTimeline: a benign observation', () => {
  it('says the observation is benign and why, on its own row only', () => {
    render(
      <MemoryRouter>
        <ShellProvider>
          <LeadTimeline lead={LEAD as never} />
        </ShellProvider>
      </MemoryRouter>,
    );
    expect(screen.getByTestId('observation-benign-89').textContent).toBe(
      `Marked benign by jordan: ${NOTE}. It counts toward no lead.`,
    );
    expect(screen.queryByTestId('observation-benign-90')).toBeNull();
  });
});
