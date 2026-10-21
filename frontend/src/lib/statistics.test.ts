// The statistic an observation stores, in words. The backend states the same
// names in soc_ai/hunting/wording.py, and tests/test_observation_wording.py
// pins the backend sentences to these.
import { describe, expect, it } from 'vitest';

import {
  isZScore,
  rateMultipleSentence,
  rerunHref,
  rerunObjective,
  statisticSentence,
} from './statistics';

// C2: a z score reads as a multiple of the rate it departed from.
describe('rateMultipleSentence', () => {
  it('states the count, the expectation and the multiple', () => {
    expect(rateMultipleSentence('residual_z', 7, 0.5)).toBe(
      '7 per hour against an expected 0.5. That is 14 times the expected rate.',
    );
    expect(rateMultipleSentence('residual_z', 3, 2)).toBe(
      '3 per hour against an expected 2. That is 1.5 times the expected rate.',
    );
    expect(rateMultipleSentence('residual_z', 1, 8)).toBe(
      '1 per hour against an expected 8. That is 0.13 of the expected rate.',
    );
    expect(rateMultipleSentence('robust_z', 40, 4)).toBe(
      '40 per hour against a median of 4. That is 10 times the median.',
    );
  });

  // Negative controls: no count, no positive baseline, or not a z score.
  it('states nothing it cannot compute', () => {
    expect(rateMultipleSentence('residual_z', null, 0.5)).toBe('');
    expect(rateMultipleSentence('residual_z', 7, 0)).toBe('');
    expect(rateMultipleSentence('documents', 7, 2)).toBe('');
    expect(isZScore('documents')).toBe(false);
    expect(isZScore('residual_z')).toBe(true);
  });
});

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
      '0 documents from the log source in the hours it stopped. The baseline expects 412 in those hours.',
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

// W6: the objective names what to explain, on which host, over which hours.
describe('rerunObjective in analyst words', () => {
  const query =
    'source.ip:"192.0.2.10" AND @timestamp:["2026-10-05T04:00:00Z" TO "2026-10-05T05:00:00Z"] | groupby destination.ip';

  it('names the host, the hours and the query', () => {
    expect(rerunObjective(query, '192.0.2.10', { dimension: 'connection_rate' })).toBe(
      'Explain the connections from 192.0.2.10 between 04:00 and 05:00 UTC on 2026-10-05. ' +
        `The query below shows the events.\n\n${query}`,
    );
  });

  it('names the member of a set departure and a window across midnight', () => {
    const q = 'destination.ip:"192.0.2.10" AND @timestamp:["2026-10-04T22:00:00Z" TO "2026-10-05T01:00:00Z"]';
    expect(rerunObjective(q, '192.0.2.10', { dimension: 'served_ports', member: '445' })).toBe(
      'Explain the connections to port 445 on 192.0.2.10 between 2026-10-04 22:00 and ' +
        `2026-10-05 01:00 UTC. The query below shows the events.\n\n${q}`,
    );
  });

  // Negative control: the objective names no tool and no tool argument.
  it('names no tool', () => {
    for (const dimension of [null, 'connection_rate', 'dns_names', 'logon_users']) {
      const text = rerunObjective(query, '192.0.2.10', { dimension, member: 'x' });
      expect(text).not.toMatch(/\bt_[a-z_]+|time_range_minutes|OQL/);
    }
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
