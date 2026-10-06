// The statistic an observation stores, in words. The backend states the same
// names in soc_ai/hunting/wording.py, and tests/test_observation_wording.py
// pins the backend sentences to these.
import { describe, expect, it } from 'vitest';

import { rerunHref, rerunObjective, statisticSentence } from './statistics';

describe('statisticSentence', () => {
  it('states each statistic the sweep writes', () => {
    expect(statisticSentence('documents', 6, 2)).toBe(
      '6 documents in the recent window. The set it is new to holds 2 members.',
    );
    expect(statisticSentence('documents', 1, null)).toBe('1 document matched.');
    expect(statisticSentence('hour_documents', 14, 0)).toBe(
      '14 documents in an hour with no activity in the baseline.',
    );
    expect(statisticSentence('estate_hosts', 0, 40)).toBe('0 of 40 profiled hosts hold this member.');
    expect(statisticSentence('estate_hosts', 1, 40)).toBe('1 of 40 profiled hosts holds this member.');
    expect(statisticSentence('hosts_departing', 3, 1)).toBe(
      '3 hosts gained this member in one sweep. 1 host held it before.',
    );
    expect(statisticSentence('peer_share', 0, 5)).toBe('0 of 5 peers in the role hold this member.');
    expect(statisticSentence('residual_z', 90, 100)).toBe(
      'A residual z of 90 against an expected 100 per hour for that hour of the week.',
    );
  });

  it('states the statistics the learned detectors write', () => {
    expect(statisticSentence('plane_documents', 0, 412)).toBe(
      '0 documents on the silent plane in the silent hours. The baseline expects 412 in those hours.',
    );
    expect(statisticSentence('chain_minutes', 3.5, 2)).toBe(
      'The attempt came 3.5 minutes after the session. The host held 2 learned outbound edges.',
    );
    expect(statisticSentence('chain_minutes', 1, 1)).toBe(
      'The attempt came 1 minute after the session. The host held 1 learned outbound edge.',
    );
  });

  it('states nothing for a row with no statistic', () => {
    expect(statisticSentence(null, null, null)).toBe('');
    expect(statisticSentence('documents', null, 2)).toBe('');
    expect(statisticSentence(undefined, 3, 2)).toBe('');
  });

  it('names a statistic it does not know with its value', () => {
    expect(statisticSentence('something_new', 2.5, 1)).toBe('something_new 2.5 against a baseline of 1.');
  });
});

describe('rerunHref', () => {
  it('opens the composer with the query in the objective', () => {
    const query = 'source.ip:"192.0.2.10" AND destination.port:4444';
    const href = rerunHref(query, '192.0.2.10');
    expect(href.startsWith('/hunts?new=1&objective=')).toBe(true);
    expect(decodeURIComponent(href.split('objective=')[1])).toBe(rerunObjective(query, '192.0.2.10'));
    expect(rerunObjective(query, '192.0.2.10')).toContain(query);
  });
});
