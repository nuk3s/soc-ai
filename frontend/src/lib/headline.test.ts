// The verdict headline in plain words (dogfood 2026-10-06, investigation C1).
// The negative controls: a parenthesis that holds words, an address or a
// domain stays in the headline.
import { describe, expect, it } from 'vitest';
import { isFieldPath, plainHeadline } from './headline';

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
