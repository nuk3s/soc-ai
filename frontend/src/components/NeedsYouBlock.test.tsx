// The Needs-you block of the bell panel and the Notifications screen.
//
// Production 2026-10-14: the badge read 309 and the panel listed 12 shadow
// hits. The block states every part of the count, with its scope in words, so
// the numbers on the panel add up to the number on the bell.
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';
import { describe, expect, it } from 'vitest';

import type { NeedsYouCount } from '../lib/api';
import { needsYouLines } from '../lib/needsYou';
import { NeedsYouBlock } from './NeedsYouBlock';

const PROD: NeedsYouCount = {
  leads_needing_decision: 7,
  unread_shadow_hits: 300,
  untriaged_groups: 0,
  needs_more_info: 2,
  pending_actions: 0,
  total: 309,
  unknown: [],
  alert_window: '7d',
  verdict_window: '30d',
  alert_floor: false,
};

const lineText = (key: string) => screen.getByTestId(`needs-you-part-${key}`).textContent;

describe('needsYouLines', () => {
  it('holds one line per part that is not zero, and the lines add up to the total', () => {
    const lines = needsYouLines(PROD);
    expect(lines.map((l) => l.key)).toEqual([
      'leads_needing_decision',
      'unread_shadow_hits',
      'needs_more_info',
    ]);
    expect(lines.reduce((sum, l) => sum + (l.count ?? 0), 0)).toBe(PROD.total);
  });

  it('names the scope of each part in words', () => {
    const every = needsYouLines({
      ...PROD,
      untriaged_groups: 4,
      pending_actions: 1,
      total: 314,
    });
    expect(every.map((l) => `${l.text}, ${l.scope}`)).toEqual([
      '7 leads wait on a decision, all open',
      '300 shadow hits are unread, all unread',
      '4 alert groups have no verdict, last 7 days',
      '2 verdicts need more info, last 30 days',
      '1 recommended action waits for you, last 30 days',
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

describe('NeedsYouBlock', () => {
  const mount = (data: NeedsYouCount | null, failed = false) =>
    render(
      <MemoryRouter>
        <NeedsYouBlock state={{ data, failed, refetch: () => {} }} />
      </MemoryRouter>,
    );

  it('links each part to the list that holds it', () => {
    mount(PROD);
    expect(lineText('unread_shadow_hits')).toBe('300 shadow hits are unread, all unread');
    expect(lineText('leads_needing_decision')).toBe('7 leads wait on a decision, all open');
    expect(lineText('needs_more_info')).toBe('2 verdicts need more info, last 30 days');
    expect(screen.getByRole('link', { name: '300 shadow hits are unread' }).getAttribute('href')).toBe(
      '/hunts?hits=unread#analytic-hits',
    );
    expect(screen.getByRole('link', { name: '7 leads wait on a decision' }).getAttribute('href')).toBe(
      '/hunts?leads=needs_decision#leads',
    );
    expect(screen.getByRole('link', { name: '2 verdicts need more info' }).getAttribute('href')).toBe(
      '/investigations?range=30d&verdict=needs_more_info',
    );
  });

  it('says when the count could not be read', () => {
    mount(null, true);
    expect(screen.getByTestId('needs-you-block').textContent).toContain(
      'Could not read what needs you.',
    );
  });

  it('says when nothing needs the analyst', () => {
    mount({ ...PROD, leads_needing_decision: 0, unread_shadow_hits: 0, needs_more_info: 0, total: 0 });
    expect(screen.getByTestId('needs-you-block').textContent).toContain('Nothing needs you.');
  });
});

// An older server sends no window words. The block used to throw on that
// and took the whole top bar down with it (Session.test, 2026-10-14).
describe('needsYouLines with an older server', () => {
  it('falls back to the default windows', () => {
    const lines = needsYouLines({ total: 2, unknown: [], needs_more_info: 2 } as unknown as NeedsYouCount);
    expect(lines.map((l) => l.scope)).toEqual(['last 30 days']);
  });
});
