// The verdict headline in plain words (dogfood 2026-10-06, investigation C1).
// The negative controls: a parenthesis that holds words, an address or a
// domain stays in the headline.
import { describe, expect, it } from 'vitest';
import { isFieldPath, plainHeadline, plainText, splitHeadline } from './headline';

describe('plainHeadline', () => {
  it('moves a list of field paths out of the headline', () => {
    const out = plainHeadline(
      'The payload is a benign probe (alert.rule_metadata.metadata_tags, community_id_events.1.payload_printable).',
    );
    expect(out.text).toBe('The payload is a benign probe.');
    expect(out.paths).toEqual([
      'alert.rule_metadata.metadata_tags',
      'community_id_events.1.payload_printable',
    ]);
  });

  it('names a tool in words', () => {
    expect(plainHeadline('The rule is noisy per t_rule_prevalence.').text).toBe(
      'The rule is noisy per the rule history.',
    );
    expect(plainHeadline('See t_custom_probe.').text).toBe('See the custom probe check.');
  });

  it('keeps a parenthesis of words, an address and a domain', () => {
    const text = 'A login from 10.0.0.5 (a known scanner) to example.com (example.com).';
    expect(plainHeadline(text)).toEqual({ text, paths: [] });
    expect(isFieldPath('example.com')).toBe(false);
    expect(isFieldPath('event.action')).toBe(true);
  });
});

// The headline is one sentence and the body never repeats it (review
// 2026-11-13, post wave 1). Run 01M6WEC0CG156GP1YX38YEAKV5 printed its whole
// summary in the headline type and then the same paragraph as the body.
describe('splitHeadline: no stray stop under the headline (AB5)', () => {
  // Dogfood 2026-11-17: a stored headline with no full stop left the stop of
  // the summary behind, and the body read ". At 2026-10-31T20:15:42Z blue ran".
  const HEAD = 'Blue ran a read-only collection of guest files, and no record shows an authorization';
  const SUM = `${HEAD}. At 2026-10-31T20:15:42Z blue ran qm config 137. The pair is common.`;

  it('drops the stop of the summary with the copy of the headline', () => {
    expect(splitHeadline(HEAD, SUM)).toEqual({
      headline: HEAD,
      body: 'At 2026-10-31T20:15:42Z blue ran qm config 137. The pair is common.',
    });
  });

  it('keeps the whole summary when the headline stops inside its first sentence', () => {
    // NEGATIVE CONTROL: "Blue ran" is a prefix of the summary, and the body
    // must not start with ", and no record".
    const short = 'Blue ran a read-only collection of guest files';
    expect(splitHeadline(short, SUM).body).toBe(SUM);
  });
});

describe('splitHeadline', () => {
  const SUMMARY =
    'Host ws-1 (10.20.30.5) opened a TLS session to shop.example.test at 2026-11-08T01:51:30Z. ' +
    'The Zeek conn record shows state SF. Escalate and name the local application.';

  it('takes the first sentence of the summary when the stored headline is the summary', () => {
    expect(splitHeadline(SUMMARY, SUMMARY)).toEqual({
      headline: 'Host ws-1 (10.20.30.5) opened a TLS session to shop.example.test at 2026-11-08T01:51:30Z.',
      body: 'The Zeek conn record shows state SF. Escalate and name the local application.',
    });
  });

  it('takes the first sentence of the summary when no headline is stored', () => {
    expect(splitHeadline('', SUMMARY).headline).toMatch(/^Host ws-1 .*01:51:30Z\.$/);
    expect(splitHeadline(null, SUMMARY).body).toBe(
      'The Zeek conn record shows state SF. Escalate and name the local application.',
    );
  });

  it('keeps a stored headline of one sentence and drops its copy from the body', () => {
    const head = 'Host ws-1 (10.20.30.5) opened a TLS session to shop.example.test at 2026-11-08T01:51:30Z.';
    expect(splitHeadline(head, SUMMARY)).toEqual({
      headline: head,
      body: 'The Zeek conn record shows state SF. Escalate and name the local application.',
    });
  });

  it('cuts a stored headline of two sentences to its first sentence', () => {
    const out = splitHeadline('The payload confirms the exploit. A campaign runs.', SUMMARY);
    expect(out.headline).toBe('The payload confirms the exploit.');
    expect(out.body).toBe(SUMMARY);
  });

  it('control: a distinct headline keeps the whole summary as the body', () => {
    const head = 'The captured payload confirms the exploit that the rule names';
    expect(splitHeadline(head, SUMMARY)).toEqual({ headline: head, body: SUMMARY });
  });

  it('does not end a sentence at an abbreviation', () => {
    const cases: Array<[string, string]> = [
      ['The host ran tools, e.g. nmap and curl, against the server. Escalate.', 'e.g.'],
      ['The rule matched one path, i.e. the upload form. Escalate.', 'i.e.'],
      ['The host sent 40 MB vs. 2 MB the day before. Escalate.', 'vs.'],
      ['The host ran nmap, curl, etc. against the server. Escalate.', 'etc.'],
      ['The flow matches a beacon, cf. the earlier run. Escalate.', 'cf.'],
      ['The host sent approx. 40 MB to the address. Escalate.', 'approx.'],
      ['The run matched rule No. 4 of the catalog. Escalate.', 'No.'],
      ['E.g. a scanner sends this request to many hosts. Escalate.', 'E.g.'],
    ];
    for (const [summary, word] of cases) {
      const out = splitHeadline('', summary);
      expect(out.headline, word).toBe(summary.replace(/ Escalate\.$/, ''));
      expect(out.body, word).toBe('Escalate.');
    }
  });

  it('control: a word that ends in an abbreviation still ends a sentence', () => {
    // "canvas." and "Taxes." end in "vs" and "es", and "No." with no number
    // after it is the word "no" at the end of a sentence.
    expect(splitHeadline('', 'The page drew a canvas. Escalate.').headline).toBe('The page drew a canvas.');
    expect(splitHeadline('', 'The answer was No. The host is clean.').headline).toBe('The answer was No.');
    expect(splitHeadline('', 'The host ran nmap, curl, etc.').headline).toBe('The host ran nmap, curl, etc.');
  });

  it('control: an address or a time stamp does not end a sentence', () => {
    expect(splitHeadline('', 'A host at 10.20.30.5 sent 2.5 MB at 01:51:30Z').headline).toBe(
      'A host at 10.20.30.5 sent 2.5 MB at 01:51:30Z',
    );
  });
});

// K3: a text names a tool and a verdict in words (review 2026-11-12, console
// finding 15).
describe('plainText', () => {
  it('words a tool id and a stored verdict key', () => {
    expect(plainText('a prior true_positive stands per t_rule_prevalence')).toBe(
      'a prior true positive stands per the rule history',
    );
    expect(plainHeadline('The verdict is needs_more_info.').text).toBe('The verdict is needs more info.');
  });

  it('control: a word that holds a key inside it stays', () => {
    expect(plainText('host_t_name and not_true_positive_x')).toBe('host_t_name and not_true_positive_x');
  });
});
