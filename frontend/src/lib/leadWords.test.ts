import { describe, expect, it } from 'vitest';

import {
  HUNT_AGAIN_CLOSE,
  agoWords,
  entityCountWords,
  huntAgainWords,
  huntRecordSentence,
  moreEntityWords,
  kindCount,
  leadHuntLabel,
  leadHuntSentence,
  leadSeenSentence,
  leadStateSentence,
  leadWaitSentence,
  runTime,
  staleHuntSentence,
} from './leadWords';
import { ago } from './timeRange';

describe('entityCountWords (K6)', () => {
  it('counts hosts and accounts by name', () => {
    expect(entityCountWords([['host', '192.0.2.1']])).toBe('1 host');
    expect(entityCountWords([['host', 'a'], ['host', 'b']])).toBe('2 hosts');
    expect(entityCountWords([['host', 'a'], ['user', 'u']])).toBe('1 host and 1 account');
    expect(entityCountWords([['user', 'u']])).toBe('1 account');
  });

  // Negative control: the word "entity" never reaches the screen.
  it('never says entity', () => {
    expect(entityCountWords([])).toBe('0 hosts');
    expect(entityCountWords([['host', 'a'], ['user', 'u']])).not.toMatch(/entit/);
  });
});

describe('leadSeenSentence', () => {
  const obs = (kind: string, at: string) => ({ kind, born_at: at, observed_at: at, evidence: null });

  it('counts by type in the order the types appear, and names the account', () => {
    expect(
      leadSeenSentence({
        entities: [['user', 'domainadmin']],
        kinds: ['catalog_match'],
        observations: [
          obs('catalog_match', '2026-10-06T03:00:00Z'),
          obs('alert', '2026-10-06T01:00:00Z'),
          obs('catalog_match', '2026-10-06T00:30:00Z'),
        ],
      }),
    ).toBe('soc-ai saw 2 analytic matches and 1 triaged alert on the account domainadmin in 3 hours.');
  });

  it('names the machine and its address, and counts the other entities', () => {
    const lead = {
      entities: [['host', '192.0.2.33']],
      kinds: ['above_baseline'],
      observations: [obs('above_baseline', '2026-10-06T03:00:00Z')],
    };
    expect(leadSeenSentence(lead, 'adguard2')).toBe(
      'soc-ai saw 1 rate spike on adguard2 at 192.0.2.33 in 1 hour.',
    );
    expect(leadSeenSentence(lead)).toBe('soc-ai saw 1 rate spike on 192.0.2.33 in 1 hour.');
    expect(
      leadSeenSentence({ ...lead, entities: [['host', '192.0.2.33'], ['host', 'b'], ['user', 'u']] }),
    ).toBe('soc-ai saw 1 rate spike on 192.0.2.33 in 1 hour. The lead also names 1 host and 1 account.');
  });

  it('says what formed a lead whose observations are gone', () => {
    expect(
      leadSeenSentence({ entities: [['host', '192.0.2.1']], kinds: ['alert'], observations: [] }),
    ).toBe('This lead formed from triaged alerts on 192.0.2.1.');
  });

  // Negative control: a type the table does not name still counts.
  it('counts a type it does not know as observations', () => {
    expect(kindCount('new_thing', 2)).toBe('2 new thing observations');
    expect(kindCount('off_hours', 1)).toBe('1 off-hours sighting');
  });
});

describe('staleHuntSentence', () => {
  const NOW = Date.parse('2026-10-06T12:00:00Z');
  const hunt = { status: 'complete', started_at: '2026-09-19T12:00:00Z' };

  it('names the hunt age and the observations it could not see', () => {
    const obs = [
      { born_at: '2026-10-06T06:00:00Z' },
      { born_at: '2026-10-05T16:00:00Z' },
      { born_at: '2026-09-18T10:00:00Z' },
    ];
    expect(staleHuntSentence(hunt, obs, NOW)).toBe(
      'The hunt ran 17 days ago. 2 observations are newer than the hunt. Hunt again to read them.',
    );
    expect(staleHuntSentence(hunt, [obs[0]], NOW)).toBe(
      'The hunt ran 17 days ago. 1 observation is newer than the hunt. Hunt again to read them.',
    );
  });

  // Negative controls: a hunt that saw every observation, a running hunt and
  // a lead with no hunt carry no warning.
  it('says nothing when the hunt is newer than every observation', () => {
    expect(staleHuntSentence(hunt, [{ born_at: '2026-09-18T10:00:00Z' }], NOW)).toBeNull();
    expect(
      staleHuntSentence({ ...hunt, status: 'running' }, [{ born_at: '2026-10-06T06:00:00Z' }], NOW),
    ).toBeNull();
    expect(staleHuntSentence(undefined, [{ born_at: '2026-10-06T06:00:00Z' }], NOW)).toBeNull();
  });
});

describe('agoWords', () => {
  const NOW = Date.parse('2026-10-06T12:00:00Z');
  it.each([
    ['2026-10-06T11:59:30Z', 'less than a minute ago'],
    ['2026-10-06T11:55:00Z', '5 minutes ago'],
    ['2026-10-06T06:00:00Z', '6 hours ago'],
    ['2026-09-19T12:00:00Z', '17 days ago'],
  ])('reads %s as %s', (iso, words) => {
    expect(agoWords(iso, NOW)).toBe(words);
  });

  // V1-H5: one hunt read "27 days ago" in the Hunt again confirm and "26d"
  // in the hunt row. The words now count whole units, the way ago() does.
  it.each([
    ['2026-09-09T23:00:00Z', '26 days ago', '26d ago'],
    ['2026-10-05T10:00:00Z', '1 day ago', '1d ago'],
    ['2026-10-06T10:31:00Z', '1 hour ago', '1h ago'],
    ['2026-10-06T11:58:31Z', '1 minute ago', '1m ago'],
  ])('reads %s as %s, the same count as ago()', (iso, words, short) => {
    expect(agoWords(iso, NOW)).toBe(words);
    expect(ago(iso, NOW)).toBe(short);
  });
});

describe('huntRecordSentence', () => {
  const clean = { status: 'complete', outcome: 'clean' };
  const threat = { status: 'complete', outcome: 'threats' };

  it('states the threat count and the newest answer', () => {
    expect(huntRecordSentence([clean, threat, threat, threat])).toBe(
      '3 of 4 hunts found a threat. The newest hunt found none.',
    );
    expect(huntRecordSentence([threat, clean])).toBe(
      '1 of 2 hunts found a threat. The newest hunt found a threat.',
    );
    expect(huntRecordSentence([{ status: 'running', outcome: '' }, threat])).toBe(
      '1 of 2 hunts found a threat. The newest hunt is running.',
    );
    expect(huntRecordSentence([{ status: 'complete', outcome: 'failed' }, clean])).toBe(
      '0 of 2 hunts found a threat. The newest hunt could not run.',
    );
  });

  it('counts a hunt that confirmed a threat through its finding investigations', () => {
    // Lead 18 on the range read "2 of 3 hunts found a threat. The newest
    // hunt found none." over a newest hunt that read "2 of 2 findings are
    // threats" (2026-10-07).
    const confirmed = { status: 'complete', outcome: 'threats_confirmed' };
    const refuted = { status: 'complete', outcome: 'no_threat_confirmed' };
    expect(huntRecordSentence([confirmed, threat, threat])).toBe(
      '3 of 3 hunts found a threat. The newest hunt confirmed a threat.',
    );
    expect(huntRecordSentence([refuted, threat])).toBe(
      '1 of 2 hunts found a threat. The newest hunt confirmed no threat.',
    );
    expect(huntRecordSentence([{ status: 'investigating', outcome: 'investigating' }, threat])).toBe(
      '1 of 2 hunts found a threat. The newest hunt investigates its findings.',
    );
  });

  // The hunt routes send the five public outcome keys, and the lead store
  // sends its own four codes. The record reads both through lib/labels.ts.
  it('reads the public outcome keys too', () => {
    const found = { status: 'complete', outcome: 'threat_found' };
    const none = { status: 'complete', outcome: 'no_threat' };
    expect(huntRecordSentence([none, found, threat])).toBe(
      '2 of 3 hunts found a threat. The newest hunt found none.',
    );
    expect(huntRecordSentence([{ status: 'complete', outcome: 'could_not_run' }, found])).toBe(
      '1 of 2 hunts found a threat. The newest hunt could not run.',
    );
    expect(huntRecordSentence([{ status: 'error', outcome: '' }, found])).toBe(
      '1 of 2 hunts found a threat. The newest hunt could not run.',
    );
  });

  // Negative control: one hunt states its own answer on its row.
  it('says nothing for fewer than two hunts', () => {
    expect(huntRecordSentence([threat])).toBeNull();
    expect(huntRecordSentence([])).toBeNull();
  });
});

describe('runTime', () => {
  it.each([
    [0, 'under 1 min'],
    [59, 'under 1 min'],
    [360, '6 min'],
    [453, '8 min'],
    [3600, '1 h'],
    [3900, '1 h 5 min'],
  ])('reads %i seconds as %s', (sec, words) => {
    expect(runTime(sec)).toBe(words);
  });
});

describe('leadHuntLabel', () => {
  const DONE = { status: 'complete', steps: 17, elapsed_sec: 360, threat_findings: 0 };

  it('names the type, the steps, the run time and the threat findings', () => {
    expect(leadHuntLabel(DONE)).toBe('Lead hunt · 17 steps · 6 min · 0 threat findings');
    expect(leadHuntLabel({ ...DONE, steps: 1, threat_findings: 1 })).toBe(
      'Lead hunt · 1 step · 6 min · 1 threat finding',
    );
  });

  it('says a running hunt runs and counts no finding', () => {
    expect(leadHuntLabel({ ...DONE, status: 'running', steps: 3 })).toBe(
      'Lead hunt · 3 steps · running',
    );
  });

  // Negative control: a hunt that did not complete has no threat count to state.
  it('states no threat count on a hunt that ended in error', () => {
    const label = leadHuntLabel({ ...DONE, status: 'error' });
    expect(label).toBe('Lead hunt · 17 steps · 6 min');
    expect(label).not.toContain('threat');
  });
});

// R3-I5 and R3 STE 20: the Hunt again confirm named no time and said nothing
// of the close that follows the new hunt.
describe('huntAgainWords', () => {
  const now = Date.parse('2026-10-19T12:00:00Z');
  it('states when the hunt on record ran and how long it took', () => {
    expect(
      huntAgainWords({ started_at: '2026-09-29T12:00:00Z', elapsed_sec: 1060 }, now),
    ).toEqual({ head: 'This lead has a hunt from 20 days ago.', run: 'That hunt ran 18 min.' });
  });

  it('states no time the record does not hold', () => {
    expect(huntAgainWords(null, now)).toEqual({ head: 'This lead has a hunt.', run: null });
    expect(huntAgainWords({ started_at: null, elapsed_sec: 0 }, now)).toEqual({
      head: 'This lead has a hunt.',
      run: null,
    });
    expect(HUNT_AGAIN_CLOSE).toBe(
      'soc-ai closes the lead when the new hunt finds no threat, or when every threat finding ' +
        'of the hunt that names an entity has a verdict.',
    );
  });
});

describe('moreEntityWords (R3 STE 7)', () => {
  it('puts "more" before the noun', () => {
    expect(moreEntityWords([['host', 'a']])).toBe('1 more host');
    expect(moreEntityWords([['host', 'a'], ['host', 'b']])).toBe('2 more hosts');
    expect(moreEntityWords([['user', 'u']])).toBe('1 more account');
    expect(moreEntityWords([['host', 'a'], ['host', 'b'], ['user', 'u']])).toBe(
      '3 more: 2 hosts and 1 account',
    );
  });
});

// F5 (production review 2026-11-12). The lead page gave the decision in
// pieces: a pill, a helper line about a hunt that had already run, two
// banners and a weight behind a toggle. One line now states what the hunt
// concluded and what the lead waits on.
describe('leadHuntSentence', () => {
  const NOW = Date.parse('2026-11-12T12:00:00Z');
  const hunt = (over: Record<string, unknown>) => ({
    status: 'complete',
    outcome: 'clean',
    started_at: '2026-10-04T12:00:00Z',
    ...over,
  });

  it('states when the newest hunt ran and what it found', () => {
    expect(leadHuntSentence({ hunts: [hunt({})] }, NOW)).toBe(
      'The newest hunt ran 39 days ago and found no threat.',
    );
    expect(leadHuntSentence({ hunts: [hunt({ outcome: 'threats' })] }, NOW)).toBe(
      'The newest hunt ran 39 days ago and found a threat.',
    );
    expect(leadHuntSentence({ hunts: [hunt({ outcome: 'threats_confirmed' })] }, NOW)).toBe(
      'The newest hunt ran 39 days ago and confirmed a threat.',
    );
    expect(leadHuntSentence({ hunts: [hunt({ outcome: 'gap' })] }, NOW)).toBe(
      'The newest hunt ran 39 days ago. It found no threat and reported a visibility gap.',
    );
  });

  it('states that no hunt ran', () => {
    expect(leadHuntSentence({ hunts: [] }, NOW)).toBe('No hunt ran on this lead.');
  });

  it('keeps an earlier threat beside a newer clean hunt', () => {
    expect(leadHuntSentence({ hunts: [hunt({})], hunt_threat_count: 1 }, NOW)).toBe(
      'The newest hunt ran 39 days ago and found no threat. An earlier hunt found a threat.',
    );
  });

  // Negative controls: a hunt with no result claims none.
  it('claims no result for a hunt that runs or that could not run', () => {
    expect(leadHuntSentence({ hunts: [hunt({ status: 'running', outcome: '' })] }, NOW)).toBe(
      'A hunt runs on this lead now.',
    );
    expect(leadHuntSentence({ hunts: [hunt({ status: 'investigating', outcome: 'threats' })] }, NOW)).toBe(
      'The newest hunt investigates its findings now.',
    );
    expect(leadHuntSentence({ hunts: [hunt({ status: 'error', outcome: 'failed' })] }, NOW)).toBe(
      'The newest hunt could not run.',
    );
    expect(leadHuntSentence({ hunts: [hunt({ outcome: 'no_answer' })] }, NOW)).toBe(
      'The newest hunt ran 39 days ago and gave no answer.',
    );
  });

  it('reads the lead record when the server names no hunt list', () => {
    expect(
      leadHuntSentence({ hunt_id: 'H', hunt_status: 'complete', hunt_outcome: 'clean' }, NOW),
    ).toBe('The newest hunt found no threat.');
    expect(leadHuntSentence({ hunt_id: null }, NOW)).toBe('No hunt ran on this lead.');
  });
});

describe('leadWaitSentence', () => {
  it('names who holds the next move in each state', () => {
    expect(leadWaitSentence({ state: 'new' })).toBe(
      'The lead waits on your decision: hunt it or dismiss it.',
    );
    expect(leadWaitSentence({ state: 'new', queued: true })).toBe(
      'The lead waits on auto-hunt. Its hunt starts within a minute.',
    );
    expect(leadWaitSentence({ state: 'in_progress' })).toBe('The lead waits on the hunt.');
    expect(leadWaitSentence({ state: 'hunted' })).toBe(
      'The lead waits on your decision: dismiss it or hunt again.',
    );
    expect(leadWaitSentence({ state: 'hunted', verdictToDecide: true })).toBe(
      'The lead waits on your decision: close it on the investigation or keep it open.',
    );
    expect(leadWaitSentence({ state: 'fleet_condition' })).toBe(
      'The lead is a fleet condition. It waits on no decision.',
    );
  });

  it('says a closed lead waits on nothing, and who closed it', () => {
    expect(leadWaitSentence({ state: 'dismissed' })).toBe(
      'An analyst dismissed the lead. It waits on nothing.',
    );
    expect(leadWaitSentence({ state: 'dismissed', closedBySocAi: true })).toBe(
      'soc-ai closed the lead. It waits on nothing.',
    );
    expect(leadWaitSentence({ state: 'promoted' })).toBe(
      'An investigation closed the lead. It waits on nothing.',
    );
    expect(leadWaitSentence({ state: 'promoted', closedBySocAi: true })).toBe(
      'soc-ai closed the lead. It waits on nothing.',
    );
  });
});

describe('leadStateSentence', () => {
  it('is the three sentences in order: seen, hunt, wait', () => {
    const NOW = Date.parse('2026-11-12T12:00:00Z');
    expect(
      leadStateSentence(
        {
          entities: [['host', '192.0.2.33']],
          kinds: ['above_baseline'],
          observations: [
            { kind: 'above_baseline', born_at: '2026-10-06T03:00:00Z', observed_at: '2026-10-06T03:00:00Z', evidence: null },
          ],
          hunts: [{ status: 'complete', outcome: 'clean', started_at: '2026-10-04T12:00:00Z' }],
        },
        { state: 'hunted', machineName: 'adguard2' },
        NOW,
      ),
    ).toBe(
      'soc-ai saw 1 rate spike on adguard2 at 192.0.2.33 in 1 hour. ' +
        'The newest hunt ran 39 days ago and found no threat. ' +
        'The lead waits on your decision: dismiss it or hunt again.',
    );
  });
});
