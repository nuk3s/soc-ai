import { describe, expect, it } from 'vitest';
import { citedEventIds, findEventIds, splitEventIds } from './eventIds';

const ID = 'UbhH2KABxYz0123456_q';

describe('citedEventIds', () => {
  it('keeps id citations only, once each', () => {
    expect(
      citedEventIds([
        { text: ID, kind: 'id', target: ID },
        { text: ID, kind: 'id', target: ID },
        { text: '(path alert.rule)', kind: 'path', target: 'alert.rule' },
      ]),
    ).toEqual([ID]);
  });
});

describe('splitEventIds', () => {
  it('cuts an id out of prose', () => {
    expect(splitEventIds(`seen in (${ID}).`)).toEqual([
      { t: 'text', v: 'seen in (' },
      { t: 'id', v: ID },
      { t: 'text', v: ').' },
    ]);
  });

  it('links a known id of any shape', () => {
    expect(findEventIds('see ev-1 and ev-2', ['ev-1'])).toEqual(['ev-1']);
  });

  it('leaves words, URLs and hashes as text', () => {
    // Negative controls: id-length words and id-shaped runs inside a longer
    // token are the paths a loose pattern would wrongly cut.
    expect(findEventIds('internationalization')).toEqual([]);
    expect(findEventIds(`https://example.test/${ID}x`)).toEqual([]);
    expect(findEventIds('d41d8cd98f00b204e9800998ecf8427e')).toEqual([]);
  });
});
