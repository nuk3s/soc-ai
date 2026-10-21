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
  leadWhySentence,
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

describe('leadWhySentence', () => {
  const obs = (kind: string, at: string) => ({ kind, born_at: at, observed_at: at, evidence: null });

  it('counts by type in the order the types appear', () => {
    expect(
      leadWhySentence({
        entities: [['user', 'domainadmin']],
        kinds: ['catalog_match'],
        observations: [
          obs('catalog_match', '2026-10-06T03:00:00Z'),
          obs('alert', '2026-10-06T01:00:00Z'),
          obs('catalog_match', '2026-10-06T00:30:00Z'),
        ],
      }),
    ).toBe('Why this is a lead: 2 analytic matches and 1 triaged alert on one account in 3 hours.');
  });

  it('says what formed a lead whose observations are gone', () => {
    expect(
      leadWhySentence({ entities: [['host', '192.0.2.1']], kinds: ['alert'], observations: [] }),
    ).toBe('Why this is a lead: it formed from triaged alerts on one host.');
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
