// The lead timeline after the round 2 verify of the 2026-10-19 dogfood.
//
// R3-D4 residual: lead 5 read "1 investigated finding" while two findings of
// its hunt shared one investigation, and the stepper counted two.
// V1-H2: the row "soc-ai closed the lead" wore the chip "investigation
// opened". V1-H3: the close sentence said "Every finding of the hunt has a
// verdict." over observations that have none.
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import { promotedFindingSentence } from '../lib/leadWords';
import { ShellProvider } from '../shell/ShellContext';
import { LeadTimeline, decisionSentence } from './LeadTimeline';

const RUN = {
  investigation_id: '01M59W451530W107Q50PPAPA5N',
  hunt_id: 'H-5',
  finding_ordinal: 0,
  finding_title: 'Credential abuse on the domain controller',
  promoted_by: 'system:hunt',
  promoted_at: '2026-10-19T10:00:00Z',
  status: 'complete',
  verdict: 'true_positive',
  confidence: 0.72,
};

const CLOSE = {
  action: 'promoted',
  at: '2026-10-19T10:30:00Z',
  by: 'system:hunt',
  reason: 'finding_verdict',
  note: null,
  hunt_id: 'H-5',
  investigation_id: RUN.investigation_id,
};

const LEAD = {
  id: 5,
  status: 'promoted',
  formed_at: '2026-09-17T10:00:00Z',
  updated_at: null,
  entities: [['host', '192.0.2.10']],
  kinds: ['above_baseline'],
  weight_at_formation: 1,
  weight_now: 0.5,
  scope_count: 1,
  hunt_id: 'H-5',
  shadow: false,
  single_signal: false,
  dismissed_reason: null,
  dismissed_note: null,
  dismissed_by: null,
  dismissed_at: null,
  investigation_id: RUN.investigation_id,
  dismiss_reasons: [],
  decisions: [CLOSE],
  promoted_findings: [{ ...RUN, shared_with: [1] }],
  observations: [],
};

function mount(lead: object = LEAD) {
  return render(
    <MemoryRouter>
      <ShellProvider>
        <LeadTimeline lead={lead as never} />
      </ShellProvider>
    </MemoryRouter>,
  );
}

describe('the lead timeline counts findings (R3-D4)', () => {
  it('counts every finding an investigation covers', () => {
    mount();
    expect(screen.getByText('Timeline · 0 observations · 1 decision · 2 investigated findings')).toBeTruthy();
  });

  it('names the finding that shares the investigation', () => {
    expect(promotedFindingSentence({ ...RUN, shared_with: [1] })).toBe(
      'soc-ai opened an investigation on finding F1. F2 shares this investigation. ' +
        'Investigation 01M59W451530W107Q50PPAPA5N: true positive 0.72.',
    );
    expect(promotedFindingSentence({ ...RUN, shared_with: [1, 3] })).toBe(
      'soc-ai opened an investigation on finding F1. F2 and F4 share this investigation. ' +
        'Investigation 01M59W451530W107Q50PPAPA5N: true positive 0.72.',
    );
  });

  // Control: an older server sends no shared_with. One run is one finding.
  it('counts one finding per run on an older server', () => {
    mount({ ...LEAD, promoted_findings: [RUN] });
    expect(screen.getByText('Timeline · 0 observations · 1 decision · 1 investigated finding')).toBeTruthy();
    expect(promotedFindingSentence(RUN)).toBe(
      'soc-ai opened an investigation on finding F1. ' +
        'Investigation 01M59W451530W107Q50PPAPA5N: true positive 0.72.',
    );
  });
});

describe('the close on the verdicts of a hunt (V1-H2, V1-H3)', () => {
  it('wears the chip closed', () => {
    mount();
    const row = screen.getByTestId('lead-decision');
    expect(within(row).getByText('closed')).toBeTruthy();
    expect(within(row).queryByText('investigation opened')).toBeNull();
    // Control: the row of the finding keeps its own chip.
    const finding = screen.getByTestId('lead-promoted-finding');
    expect(within(finding).getByText('investigation opened')).toBeTruthy();
  });

  it("wears the chip closed in an analyst's hand too", () => {
    mount({ ...LEAD, decisions: [{ ...CLOSE, by: 'alice' }] });
    expect(within(screen.getByTestId('lead-decision')).getByText('closed')).toBeTruthy();
  });

  // Control: a promotion of the lead itself is an opened investigation.
  it('keeps investigation opened on a promotion of the lead', () => {
    mount({ ...LEAD, decisions: [{ ...CLOSE, by: 'alice', reason: null }] });
    expect(within(screen.getByTestId('lead-decision')).getByText('investigation opened')).toBeTruthy();
  });

  it('states the rule the code closes by', () => {
    expect(decisionSentence(CLOSE)).toBe(
      'soc-ai closed the lead. Every threat finding of the hunt that names an entity has a verdict.',
    );
  });
});
