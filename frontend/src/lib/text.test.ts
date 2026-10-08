import { describe, expect, it } from 'vitest';
import * as text from './text';
import { COUNTING, firstSentence } from './text';

// The owner banned the ellipsis on 2026-10-07. middleEllipsis cut a rule name
// in the middle at 72 characters, and every list now shows the name whole.
describe('the text helpers', () => {
  it('export no helper that cuts a text at a character count', () => {
    expect(Object.keys(text)).not.toContain('middleEllipsis');
  });
  it('name a count in progress with a word and no ellipsis', () => {
    expect(COUNTING).toBe('counting');
    expect(COUNTING).not.toMatch(/…|\.\.\./);
  });
});

// A hunt objective runs to several sentences and a header line holds one.
describe('firstSentence', () => {
  it('keeps the first sentence and drops the rest', () => {
    expect(
      firstSentence('Sweep for directory replication. Say whether the two leads are one campaign.'),
    ).toBe('Sweep for directory replication.');
  });
  it('returns a sentence with no stop unchanged', () => {
    expect(firstSentence('Sweep for directory replication')).toBe(
      'Sweep for directory replication',
    );
  });
  it('keeps a question whole', () => {
    expect(firstSentence('Are the two leads one campaign? Read both.')).toBe(
      'Are the two leads one campaign?',
    );
  });
  it('trims the line it is given', () => {
    expect(firstSentence('  Sweep the host.  Then stop. ')).toBe('Sweep the host.');
  });
});
