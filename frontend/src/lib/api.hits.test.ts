// The wire contract of the Hunts spine: one hits route for the live and the
// shadow hits, one count of what waits on the analyst, and the two new lead
// filters. Pinned the way api.hunts.test.ts pins the hunt routes, so a mistyped
// path or a swapped parameter reads as a failing test here and not as a 404 an
// analyst meets later.
//
// The emit is pinned too. Four surfaces count what needs the analyst, and each
// one polls on its own timer. The emit lives in the API function rather than in
// a component, so a caller cannot forget it.
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  dismissLead,
  getAnalyticHits,
  getLeads,
  getNeedsYou,
  huntLead,
  markShadowHitRead,
  onNeedsYouChanged,
  onShadowHitsChanged,
  promoteLead,
  reopenLead,
  setAnalyticStatus,
} from './api';

let fetchMock: ReturnType<typeof vi.fn>;

const ok = (body: unknown = {}) =>
  Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) } as Response);

const fail = () =>
  Promise.resolve({
    ok: false,
    status: 503,
    json: () => Promise.resolve({ detail: 'down' }),
  } as Response);

beforeEach(() => {
  fetchMock = vi.fn(() => ok());
  vi.stubGlobal('fetch', fetchMock);
});

afterEach(() => {
  vi.unstubAllGlobals();
});

const url = (): string => String(fetchMock.mock.calls[0][0]);

describe('getAnalyticHits', () => {
  it('reads the plain hits route when it is given nothing', async () => {
    await getAnalyticHits();
    expect(url()).toBe('/api/v1/hunts/hits');
  });

  it('names the window, the filter and the limit it was given', async () => {
    await getAnalyticHits({ days: 7, filter: 'unread', limit: 20 });
    expect(url()).toBe('/api/v1/hunts/hits?days=7&filter=unread&limit=20');
  });

  it('passes the hits and the counts through', async () => {
    const body = {
      hits: [
        {
          id: 41,
          analytic_id: 'local-svc-ticket',
          analytic_title: 'A service ticket comes from a workstation',
          analytic_status: 'shadow',
          tier: 'local',
          entity_kind: 'host',
          entity_key: '10.1.2.3',
          born_at: null,
          first_seen_at: null,
          occurrences: 3,
          summary: null,
          state: 'hit',
          missing: [],
          receipts: null,
          read: false,
          lead_id: null,
          lead_status: null,
          document_count: 2,
        },
      ],
      counts: { all: 1, unread: 1, live: 0, shadow: 1 },
    };
    fetchMock = vi.fn(() => ok(body));
    vi.stubGlobal('fetch', fetchMock);

    const result = await getAnalyticHits({ filter: 'all' });
    expect(result.counts).toEqual({ all: 1, unread: 1, live: 0, shadow: 1 });
    expect(result.hits[0].document_count).toBe(2);
  });
});

describe('getNeedsYou', () => {
  it('reads the needs-you route and passes the three counts through', async () => {
    fetchMock = vi.fn(() => ok({ unread_shadow_hits: 2, leads_needing_decision: 2, total: 4 }));
    vi.stubGlobal('fetch', fetchMock);

    const result = await getNeedsYou();
    expect(url()).toBe('/api/v1/hunts/needs-you');
    expect(result).toEqual({ unread_shadow_hits: 2, leads_needing_decision: 2, total: 4 });
  });
});

describe('getLeads status aliases', () => {
  it('asks the server for the leads that need a decision', async () => {
    await getLeads('needs_decision');
    expect(url()).toBe('/api/v1/leads?status=needs_decision');
  });

  it('asks the server for the leads under a running hunt', async () => {
    await getLeads('in_progress');
    expect(url()).toBe('/api/v1/leads?status=in_progress');
  });

  it('keeps the filters it had before', async () => {
    await getLeads('all');
    expect(url()).toBe('/api/v1/leads?status=all');
  });
});

describe('the needs-you emit', () => {
  it('tells every surface after a hit is read', async () => {
    const needsYou = vi.fn();
    const shadowHits = vi.fn();
    const stopA = onNeedsYouChanged(needsYou);
    const stopB = onShadowHitsChanged(shadowHits);
    try {
      await markShadowHitRead(41);
      expect(needsYou).toHaveBeenCalledTimes(1);
      expect(shadowHits).toHaveBeenCalledTimes(1);
    } finally {
      stopA();
      stopB();
    }
  });

  it('tells every surface after each write on a lead', async () => {
    const heard = vi.fn();
    const stop = onNeedsYouChanged(heard);
    try {
      await huntLead(6);
      await dismissLead(6, 'benign_repeat');
      await reopenLead(6);
      await promoteLead(6);
      expect(heard).toHaveBeenCalledTimes(4);
    } finally {
      stop();
    }
  });

  it('tells every surface after an analytic changes status', async () => {
    const heard = vi.fn();
    const stop = onNeedsYouChanged(heard);
    try {
      await setAnalyticStatus('local-svc-ticket', 'live', 'it proved itself');
      expect(heard).toHaveBeenCalledTimes(1);
    } finally {
      stop();
    }
  });

  it('says nothing when the server refused the write', async () => {
    fetchMock = vi.fn(() => fail());
    vi.stubGlobal('fetch', fetchMock);
    const heard = vi.fn();
    const stop = onNeedsYouChanged(heard);
    try {
      await expect(markShadowHitRead(41)).rejects.toThrow();
      expect(heard).not.toHaveBeenCalled();
    } finally {
      stop();
    }
  });

  it('stops telling a surface that has gone away', async () => {
    const heard = vi.fn();
    onNeedsYouChanged(heard)();
    await markShadowHitRead(41);
    expect(heard).not.toHaveBeenCalled();
  });
});
