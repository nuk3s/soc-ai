import { fireEvent, render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import { withStop } from '../lib/leadWords';
import { ShellProvider } from '../shell/ShellContext';
import { LeadTimeline, decisionSentence } from './LeadTimeline';

const OBS = {
  kind: 'above_baseline',
  spec_id: 'profile-connection-rate',
  summary: 'The connection rate on Monday 04:00 is 7 per hour.',
  occurrences: 1,
  first_seen_at: null,
  source: 'profile',
  shadow: false,
  weight_now: 0.5,
  birth_weight: 0.7,
  analytic_exists: true,
};

/** Lead 1 after an undo test: decisions, observations and a finding, each on
 *  its own clock. */
const LEAD = {
  id: 1,
  status: 'promoted',
  formed_at: '2026-09-17T10:00:00Z',
  updated_at: null,
  entities: [['host', '192.0.2.10']],
  kinds: ['above_baseline'],
  weight_at_formation: 1,
  weight_now: 0.5,
  scope_count: 1,
  hunt_id: null,
  shadow: false,
  single_signal: false,
  dismissed_reason: null,
  dismissed_note: null,
  dismissed_by: null,
  dismissed_at: null,
  investigation_id: 'INV-1',
  dismiss_reasons: [],
  decisions: [
    { action: 'dismissed', at: '2026-09-28T10:00:00Z', by: 'ann', reason: 'lab_host', note: null, hunt_id: null, investigation_id: null },
    { action: 'reopened', at: '2026-10-06T08:00:00Z', by: 'ann', reason: null, note: null, hunt_id: null, investigation_id: null },
  ],
  promoted_findings: [
    {
      investigation_id: '01M48EPSK80EBWHBMZ5XH0SVZM',
      hunt_id: 'H-1',
      finding_ordinal: 0,
      finding_title: 'x',
      promoted_by: 'bob',
      promoted_at: '2026-10-01T10:00:00Z',
      status: 'complete',
      verdict: 'false_positive',
      confidence: 0.9,
    },
  ],
  observations: [
    {
      ...OBS,
      id: 7,
      born_at: '2026-10-06T09:00:00Z',
      observed_at: '2026-10-05T04:50:00Z',
      evidence: null,
      rerun_query:
        'source.ip:"192.0.2.10" AND @timestamp:["2026-10-05T04:00:00Z" TO "2026-10-05T05:00:00Z"] | groupby destination.ip',
    },
    {
      ...OBS,
      id: 8,
      kind: 'catalog_match',
      born_at: '2026-09-20T09:00:00Z',
      observed_at: null,
      evidence: { first_seen: '2026-09-19T22:10:00Z', last_seen: '2026-09-20T01:30:00Z' },
    },
  ],
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

describe('LeadTimeline: one order, one clock (C3)', () => {
  it('puts every row newest first, whatever its type', () => {
    mount();
    const rows = Array.from(document.querySelectorAll('li[data-testid]')).map((li) =>
      li.getAttribute('data-testid'),
    );
    expect(rows).toEqual([
      'lead-decision', // reopened 10-06 08:00
      'observation-7', // events end 10-05 05:00
      'lead-promoted-finding', // 10-01
      'lead-decision', // dismissed 09-28
      'observation-8', // events end 09-20 01:30
    ]);
  });

  it('dates each observation by its event window, in UTC', () => {
    mount();
    expect(screen.getByTestId('observation-window-7').textContent).toBe(
      'Events 2026-10-05 04:00 to 05:00 UTC.',
    );
    expect(screen.getByTestId('observation-window-8').textContent).toBe(
      'Events 2026-09-19 22:10 to 2026-09-20 01:30 UTC.',
    );
    expect(screen.getByTestId('lead-timeline-note').textContent).toBe(
      'Newest first. Times in UTC.',
    );
  });

  // Negative control: a row with no event window and no event time says so.
  it('says when an observation has no document time', () => {
    mount({
      ...LEAD,
      observations: [{ ...LEAD.observations[1], id: 9, evidence: null, observed_at: null }],
    });
    expect(screen.getByTestId('observation-window-9').textContent).toBe(
      'Recorded 2026-09-20 09:00 UTC. No document time is on record.',
    );
  });

  it('counts every kind of row in the header', () => {
    mount();
    expect(
      screen.getByText('Timeline · 2 observations · 2 decisions · 1 investigated finding'),
    ).toBeTruthy();
    const finding = screen.getByTestId('lead-promoted-finding');
    expect(within(finding).getByText(/Investigation 01M48EPSK80EBWHBMZ5XH0SVZM: false positive 0\.90\./)).toBeTruthy();
  });
});

describe('the query of an observation (W6)', () => {
  it('copies the query, and hunts with an objective in analyst words', async () => {
    const writes: string[] = [];
    Object.defineProperty(navigator, 'clipboard', {
      configurable: true,
      value: { writeText: (text: string) => (writes.push(text), Promise.resolve()) },
    });
    mount({
      ...LEAD,
      observations: [
        {
          ...LEAD.observations[0],
          evidence: { baseline: { dimension: 'connection_rate', member: 'off', observed_count: 7 } },
        },
      ],
    });
    const row = screen.getByTestId('observation-query-7');
    fireEvent.click(within(row).getByRole('button', { name: 'Copy query' }));
    expect(await within(row).findByRole('button', { name: 'Copied' })).toBeTruthy();
    expect(writes).toEqual([(LEAD.observations[0] as { rerun_query: string }).rerun_query]);
    const href = within(row).getByRole('link', { name: 'Hunt with this query' }).getAttribute('href') ?? '';
    const objective = decodeURIComponent(href.split('objective=')[1]);
    expect(objective.startsWith(
      'Explain the connections from 192.0.2.10 between 04:00 and 05:00 UTC on 2026-10-05.',
    )).toBe(true);
    expect(objective).not.toMatch(/t_query_events_oql|time_range_minutes/);
    expect(within(row).queryByText('Run this query')).toBeNull();
  });
});

describe('a lead formed from a backtest replay', () => {
  const NOTE =
    'This lead formed from a backtest replay. A backtest replay is a measurement on an ' +
    'alert an analyst already closed. It is not live evidence.';
  const MARK = {
    action: 'formed_from_backtest',
    at: '2026-10-06T08:00:00Z',
    by: 'soc-ai',
    reason: 'backtest_replay',
    note: NOTE,
    hunt_id: null,
    investigation_id: null,
  };

  it('reads the stored note and the word "backtest replay", never the raw code', () => {
    mount({ ...LEAD, decisions: [MARK], promoted_findings: [], observations: [] });
    const row = screen.getByTestId('lead-decision');
    expect(within(row).getByText('backtest replay')).toBeTruthy();
    expect(row.textContent).toContain(NOTE);
    expect(row.textContent).not.toContain('formed_from_backtest');
    // Negative control: a mark with no stored note still reads as a sentence.
    expect(decisionSentence({ ...MARK, note: null })).toBe(
      'This lead formed from a backtest replay.',
    );
  });
});

describe('decisionSentence: a reopen names who and why (C3)', () => {
  const REOPEN = { at: null, note: null, hunt_id: null, investigation_id: null };
  it.each([
    [
      { by: 'auto-hunt', reason: 'new_type' },
      'Reopened by soc-ai. A new observation arrived, of a type the lead did not hold.',
    ],
    [{ by: 'auto-hunt', reason: null }, 'Reopened by soc-ai. A new observation arrived.'],
    [{ by: 'ann', reason: null }, 'Reopened by ann. The analyst put the lead back to decide again.'],
    [{ by: null, reason: null }, 'Reopened. The record does not name who reopened it.'],
  ])('reads %o', (extra, words) => {
    expect(decisionSentence({ ...REOPEN, action: 'reopened', ...extra })).toBe(words);
  });
});

const BASE = {
  at: '2026-10-06T08:00:00Z',
  by: 'alice',
  reason: 'expected_for_role',
  note: null,
  hunt_id: null,
  investigation_id: null,
};

describe('decisionSentence: one stop at the end', () => {
  it('adds no second stop to a note that ends in one', () => {
    const line = decisionSentence({ ...BASE, action: 'dismissed', note: 'log shipping.' });
    expect(line).toBe('Dismissed by alice: Expected for this role. log shipping.');
    expect(line).not.toContain('..');
  });

  // Negative control: a note with no stop still ends the sentence.
  it('adds the stop to a note that has none', () => {
    const line = decisionSentence({ ...BASE, action: 'dismissed', note: 'log shipping' });
    expect(line).toBe('Dismissed by alice: Expected for this role. log shipping.');
  });

  it('ends a dismissal with no note in one stop', () => {
    expect(decisionSentence({ ...BASE, action: 'dismissed' })).toBe(
      'Dismissed by alice: Expected for this role.',
    );
  });
});

describe('withStop', () => {
  it('keeps a question mark and an exclamation mark', () => {
    expect(withStop('Why?')).toBe('Why?');
    expect(withStop('Stop!')).toBe('Stop!');
  });
  it('trims the space after the stop', () => {
    expect(withStop('Done.  ')).toBe('Done.');
  });
});

// R3-D5: the timeline printed the raw actor "system:hunt".
describe('decisionSentence: soc-ai closes a lead on the verdicts of its hunt', () => {
  it('names soc-ai and the reason', () => {
    expect(
      decisionSentence({
        ...BASE,
        action: 'promoted',
        by: 'system:hunt',
        reason: 'finding_verdict',
      }),
    ).toBe('soc-ai closed the lead. Every threat finding of the hunt that names an entity has a verdict.');
  });

  // Control: an analyst's close on a finding verdict keeps the analyst.
  it("keeps an analyst's close in the analyst's name", () => {
    expect(
      decisionSentence({ ...BASE, action: 'promoted', by: 'alice', reason: 'finding_verdict' }),
    ).toBe('alice closed the lead on the investigation of a hunt finding.');
  });

  it('never prints a system actor', () => {
    expect(decisionSentence({ ...BASE, action: 'dismissed', by: 'system:self-heal' })).toBe(
      'Dismissed by soc-ai: Expected for this role.',
    );
  });
});
