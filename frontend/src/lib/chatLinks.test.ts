// Links in a chat answer (dogfood 2026-10-19, R1-D5 and R1-I4): the general
// chat named an address, a lead and an investigation as plain text.
import { describe, expect, it } from 'vitest';
import { linkifyChatAnswer } from './chatLinks';

const ULID = `01J${'A'.repeat(23)}`;

describe('linkifyChatAnswer', () => {
  it('links an address to its page and keeps the full stop', () => {
    expect(linkifyChatAnswer('No event touched 192.0.2.40 in the last week.')).toBe(
      'No event touched [192.0.2.40](/entity/192.0.2.40) in the last week.',
    );
    expect(linkifyChatAnswer('It ends at 198.51.100.7.')).toBe(
      'It ends at [198.51.100.7](/entity/198.51.100.7).',
    );
  });

  it('links an address with a port and leaves the port as text', () => {
    expect(linkifyChatAnswer('203.0.113.9:443 answered')).toBe(
      '[203.0.113.9](/entity/203.0.113.9):443 answered',
    );
  });

  it('links a lead and an investigation', () => {
    expect(linkifyChatAnswer('Lead 11 is open. See lead #4.')).toBe(
      '[Lead 11](/leads/11) is open. See [lead #4](/leads/4).',
    );
    expect(linkifyChatAnswer(`Investigation ${ULID} holds it.`)).toBe(
      `Investigation [${ULID}](/investigation/${ULID}) holds it.`,
    );
  });

  it('leaves code, links, URLs, networks and longer numbers alone', () => {
    // Each of these is the path a naive replace would break.
    const kept = [
      'Run `host 192.0.2.40` first.',
      '```\nsrc 192.0.2.40\n```',
      'See [the host](/hosts/192.0.2.40).',
      'Open http://192.0.2.40/admin now.',
      'The block 192.0.2.0/24 is internal.',
      'Version 1.2.3.4.5 shipped.',
      'Leader 11 and misleading 4.',
      'The id UbhH2KABxYz0123456_q is a document.',
    ];
    for (const text of kept) expect(linkifyChatAnswer(text)).toBe(text);
  });

  it('links outside a code span on the same line', () => {
    expect(linkifyChatAnswer('`192.0.2.1` talked to 192.0.2.2')).toBe(
      '`192.0.2.1` talked to [192.0.2.2](/entity/192.0.2.2)',
    );
  });
});
