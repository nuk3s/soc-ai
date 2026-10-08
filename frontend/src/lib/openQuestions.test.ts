// The open question of an unsettled verdict, read from the rationale when the
// run recorded none (dogfood 2026-10-06, investigation W2). The negative
// controls: a rationale that names no gap gives null, and an address does not
// split a sentence.
import { describe, expect, it } from 'vitest';
import { gapSentence, sentences } from './openQuestions';

describe('gapSentence', () => {
  it('picks the sentence of the rationale that names the gap', () => {
    expect(
      gapSentence(
        'The scan came from 10.0.0.5. The auth log of the target would confirm a login after the scan.',
      ),
    ).toBe('The auth log of the target would confirm a login after the scan.');
  });

  it('falls back to the summary', () => {
    expect(gapSentence('A port scan.', 'No evidence shows a login. Nothing else.')).toBe(
      'No evidence shows a login.',
    );
  });

  it('gives null when no text names a gap', () => {
    expect(gapSentence('A port scan from a known scanner.', 'It is routine.')).toBeNull();
    expect(gapSentence(null, undefined)).toBeNull();
  });

  it('keeps an address whole', () => {
    expect(sentences('From 10.0.0.1 to 10.0.0.2. Done.')).toEqual(['From 10.0.0.1 to 10.0.0.2.', 'Done.']);
  });
});
