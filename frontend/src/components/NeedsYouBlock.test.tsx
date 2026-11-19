// The Needs-you block of the bell panel and the Notifications screen.
//
// Production 2026-10-14: the badge read 309 and the panel listed 12 shadow
// hits. The block states every decision part of the count, with its scope in
// words, so the numbers on the panel add up to the number on the bell.
// Production review 2026-11-12 (ui-core 4): the unread shadow hits are review
// work. They have their own neutral line, and the badge leaves them out.
import { render, screen, within } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import type { NeedsYouCount } from '../lib/api';
import { decisionCount, decisionFloor, needsYouLines, needsYouReviewLine, scopeOfWindow } from '../lib/needsYou';
import { NeedsYouBlock } from './NeedsYouBlock';

const PROD: NeedsYouCount = {
  leads_needing_decision: 7,
  unread_shadow_hits: 300,
  untriaged_groups: 0,
  needs_more_info: 2,
  pending_actions: 0,
  decisions: 9,
  review: 300,
  total: 309,
  unknown: [],
  alert_window: '7d',
  verdict_window: '30d',
  alert_floor: false,
};

// The server of this round: the investigations that wait, at any age.
const NOW_SERVER: NeedsYouCount = {
  campaigns: 0,
  leads_needing_decision: 0,
  unread_shadow_hits: 0,
  untriaged_groups: 0,
  needs_more_info: 0,
  pending_actions: 0,
  investigations_waiting: 0,
  decisions: 0,
  review: 0,
  total: 0,
  unknown: [],
  alert_window: '7d',
  verdict_window: 'all',
  alert_floor: false,
};

const lineText = (key: string) => screen.getByTestId(`needs-you-part-${key}`).textContent;

describe('needsYouLines', () => {
  it('holds one line per decision part that is not zero, and the lines add up to the decisions', () => {
    const lines = needsYouLines(PROD);
    expect(lines.map((l) => l.key)).toEqual(['investigations_waiting', 'leads_needing_decision']);
    expect(lines.reduce((sum, l) => sum + (l.count ?? 0), 0)).toBe(PROD.decisions);
  });

  // The server sum: one investigation with two waiting actions is one
  // decision. Two lines said "1 verdict needs more info" and "2 recommended
  // actions wait", and they added up to 3 over a list of 2 investigations.
  it('states the investigations that wait in one line, each investigation once', () => {
    const data: NeedsYouCount = {
      ...NOW_SERVER,
      needs_more_info: 1,
      pending_actions: 2,
      investigations_waiting: 2,
      decisions: 2,
    };
    const lines = needsYouLines(data);
    expect(lines.map((l) => `${l.text}, ${l.scope}`)).toEqual(['2 investigations wait on your decision, at any age']);
    expect(lines[0].to).toBe('/needs-you?type=investigation');
    expect(lines.reduce((sum, l) => sum + (l.count ?? 0), 0)).toBe(decisionCount(data));
    expect(needsYouLines({ ...data, investigations_waiting: 1, decisions: 1 })[0].text).toBe(
      '1 investigation waits on your decision',
    );
  });

  it('orders the lines campaigns, investigations, leads, alert groups', () => {
    const data: NeedsYouCount = {
      ...NOW_SERVER,
      campaigns: 1,
      investigations_waiting: 2,
      leads_needing_decision: 1,
      untriaged_groups: 3,
      decisions: 7,
    };
    const lines = needsYouLines(data);
    expect(lines.map((l) => l.key)).toEqual([
      'campaigns',
      'investigations_waiting',
      'leads_needing_decision',
      'untriaged_groups',
    ]);
    expect(lines.reduce((sum, l) => sum + (l.count ?? 0), 0)).toBe(7);
  });

  // NEGATIVE CONTROL. A failed read of a detail is no floor. A failed read of
  // a part of the number is one.
  it('marks a floor only for a part of the number', () => {
    expect(decisionFloor({ ...NOW_SERVER, pending_actions: null, unknown: ['pending_actions'] })).toBe(false);
    expect(
      decisionFloor({ ...NOW_SERVER, investigations_waiting: null, unknown: ['investigations_waiting'] }),
    ).toBe(true);
    const lines = needsYouLines({ ...NOW_SERVER, investigations_waiting: null, unknown: ['investigations_waiting'] });
    expect(lines[0]).toMatchObject({ key: 'investigations_waiting', count: null });
    expect(lines[0].unknown).toBe('Could not count the investigations that wait.');
  });

  // NEGATIVE CONTROL. 300 unread hits are no decision line.
  it('leaves the shadow hits to the review line', () => {
    expect(needsYouLines(PROD).some((l) => l.key === 'unread_shadow_hits')).toBe(false);
    const review = needsYouReviewLine(PROD)!;
    expect(`${review.text}, ${review.scope}`).toBe('300 shadow hits to review, all unread');
    expect(review.to).toBe('/hunts?hits=unread#analytic-hits');
    expect(needsYouReviewLine({ ...PROD, review: 0, unread_shadow_hits: 0 })).toBeNull();
    expect(needsYouReviewLine({ ...PROD, review: null })!.count).toBeNull();
  });

  it('names the scope of each part in words', () => {
    const every = needsYouLines({
      ...PROD,
      untriaged_groups: 4,
      pending_actions: 1,
      total: 314,
    });
    expect(every.map((l) => `${l.text}, ${l.scope}`)).toEqual([
      '3 investigations wait on your decision, last 30 days',
      '7 leads wait on a decision, all open',
      '4 alert groups have no verdict, last 7 days',
    ]);
  });

  it('keeps a part the server could not read, and says so', () => {
    const lines = needsYouLines({
      ...PROD,
      untriaged_groups: null,
      unknown: ['untriaged_groups'],
    });
    const alerts = lines.find((l) => l.key === 'untriaged_groups')!;
    expect(alerts.count).toBeNull();
    expect(alerts.unknown).toBe('Could not count the alert groups. The grid did not answer.');
  });

  it('marks the alert part as a floor when the grid capped the group list', () => {
    const lines = needsYouLines({ ...PROD, untriaged_groups: 500, alert_floor: true, total: 809 });
    expect(lines.find((l) => l.key === 'untriaged_groups')!.text).toBe(
      '500+ alert groups have no verdict',
    );
  });

  it('holds no line when nothing needs the analyst', () => {
    expect(
      needsYouLines({
        ...PROD,
        leads_needing_decision: 0,
        unread_shadow_hits: 0,
        needs_more_info: 0,
        total: 0,
      }),
    ).toEqual([]);
  });
});

describe('needsYouLines with campaigns', () => {
  it('puts the campaigns first, links them to the list that waits and counts them in the decisions', () => {
    const data = { ...PROD, campaigns: 2, decisions: 11 };
    const lines = needsYouLines(data);
    expect(lines[0]).toMatchObject({
      key: 'campaigns',
      count: 2,
      text: '2 campaigns wait on your decision',
      scope: 'at any age',
      to: '/needs-you?type=campaign',
    });
    expect(lines.reduce((sum, l) => sum + (l.count ?? 0), 0)).toBe(data.decisions);
    expect(needsYouLines({ ...data, campaigns: 1 })[0].text).toBe('1 campaign waits on your decision');
  });

  it('sums the campaigns into the count of a server that sends no sum', () => {
    const { decisions: _d, ...older } = { ...PROD, campaigns: 2 };
    expect(decisionCount(older)).toBe(11);
  });

  it('holds no campaign line for an older server, and keeps a part it could not read', () => {
    expect(needsYouLines(PROD).some((l) => l.key === 'campaigns')).toBe(false);
    const unread = needsYouLines({ ...PROD, campaigns: null, unknown: ['campaigns'] });
    expect(unread[0]).toMatchObject({ key: 'campaigns', count: null, unknown: 'Could not count the campaigns.' });
    expect(decisionFloor({ ...PROD, campaigns: null, unknown: ['campaigns'] })).toBe(true);
  });
});

describe('NeedsYouBlock', () => {
  const mount = (data: NeedsYouCount | null, failed = false) =>
    render(
      <MemoryRouter>
        <NeedsYouBlock state={{ data, failed, refetch: () => {} }} />
      </MemoryRouter>,
    );

  // NY4. A line that states waiting work opens the one list with a type
  // filter, and no other list. The review line keeps the shadow hits.
  it('links each decision part to the Needs you page with its type filter', () => {
    mount(PROD);
    expect(screen.queryByTestId('needs-you-part-unread_shadow_hits')).toBeNull();
    expect(screen.getByTestId('needs-you-review').textContent).toBe('300 shadow hits to review, all unread');
    expect(lineText('leads_needing_decision')).toBe('7 leads wait on a decision, all open');
    expect(lineText('investigations_waiting')).toBe('2 investigations wait on your decision, last 30 days');
    // A scope never breaks inside.
    const scope = screen.getAllByTestId('scope-of-part')[0];
    expect(scope.className).toContain('whitespace-nowrap');
    const hits = screen.getByRole('link', { name: '300 shadow hits to review' });
    expect(hits.getAttribute('href')).toBe('/hunts?hits=unread#analytic-hits');
    // The review link is neutral. Only a decision takes the accent color.
    expect(hits.className).not.toContain('text-accent');
    expect(screen.getByRole('link', { name: '7 leads wait on a decision' }).getAttribute('href')).toBe(
      '/needs-you?type=lead',
    );
    expect(screen.getByRole('link', { name: '2 investigations wait on your decision' }).getAttribute('href')).toBe(
      '/needs-you?type=investigation',
    );
    // Every decision line opens the Needs you page. Only the review line does not.
    const links = within(screen.getByTestId('needs-you-block')).getAllByRole('link');
    const others = links
      .map((l) => l.getAttribute('href') ?? '')
      .filter((href) => !href.startsWith('/needs-you'));
    expect(others).toEqual(['/hunts?hits=unread#analytic-hits']);
  });

  it('says when the count could not be read', () => {
    mount(null, true);
    expect(screen.getByTestId('needs-you-block').textContent).toContain(
      'Could not read what needs you.',
    );
  });

  it('says when nothing needs the analyst', () => {
    mount({ ...PROD, leads_needing_decision: 0, unread_shadow_hits: 0, needs_more_info: 0, decisions: 0, review: 0, total: 0 });
    expect(screen.getByTestId('needs-you-block').textContent).toContain('Nothing needs you.');
  });

  it('says nothing needs the analyst over unread hits, and states the hits apart', () => {
    mount({ ...PROD, leads_needing_decision: 0, needs_more_info: 0, decisions: 0, total: 300 });
    const block = screen.getByTestId('needs-you-block').textContent;
    expect(block).toContain('Nothing needs you.');
    expect(block).toContain('300 shadow hits to review, all unread');
  });

  it('links its heading to the Needs you page with the decision count', () => {
    mount(PROD);
    const link = screen.getByTestId('needs-you-page-link');
    expect(link.getAttribute('href')).toBe('/needs-you');
    expect(link.textContent).toBe('Needs you9');
  });

  it('marks a floor on the count of its heading', () => {
    mount({ ...PROD, unknown: ['untriaged_groups'] });
    expect(screen.getByTestId('needs-you-page-link').textContent).toBe('Needs you9+');
  });
});

// An older server sends no window words. The block used to throw on that
// and took the whole top bar down with it (Session.test, 2026-10-14).
describe('needsYouLines with an older server', () => {
  it('falls back to the default windows', () => {
    const lines = needsYouLines({ total: 2, unknown: [], needs_more_info: 2 } as unknown as NeedsYouCount);
    expect(lines.map((l) => l.scope)).toEqual(['last 30 days']);
  });

  // A server with no campaigns, no decisions and no investigations_waiting
  // field: the console sums the parts that server summed, and the one line
  // of the investigations holds the two parts behind it.
  it('sums the parts of a server with no decisions field', () => {
    const older = { ...PROD, pending_actions: 1 } as Partial<NeedsYouCount>;
    delete older.decisions;
    delete older.review;
    const data = older as NeedsYouCount;
    expect(decisionCount(data)).toBe(7 + 2 + 1);
    const lines = needsYouLines(data);
    expect(lines.map((l) => l.key)).toEqual(['investigations_waiting', 'leads_needing_decision']);
    expect(lines[0].count).toBe(3);
    expect(lines.reduce((sum, l) => sum + (l.count ?? 0), 0)).toBe(decisionCount(data));
    expect(decisionFloor({ ...data, unknown: ['pending_actions'] })).toBe(true);
  });
});

describe('scopeOfWindow', () => {
  it('reads the window "all" as at any age', () => {
    expect(scopeOfWindow('all')).toBe('at any age');
    expect(scopeOfWindow('all')).not.toContain('last');
  });

  // NEGATIVE CONTROL. A real window keeps its words.
  it('keeps the words of a window with a length', () => {
    expect(scopeOfWindow('7d')).toBe('last 7 days');
    expect(scopeOfWindow('1h')).toBe('last 1 hour');
  });
});
