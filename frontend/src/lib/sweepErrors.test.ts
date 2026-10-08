// A sweep failure reads as a sentence (dogfood 2026-10-06). The host page
// banner and the Needs attention list printed "<address>: TimeoutError:" with
// nothing after the colon.
import { describe, expect, it } from 'vitest';
import { sweepErrorList, sweepFailureSentence } from './sweepErrors';

describe('sweepFailureSentence', () => {
  it('says a timeout with no message in words', () => {
    expect(sweepFailureSentence('192.0.2.46: TimeoutError:')).toBe(
      'The sweep could not read 192.0.2.46: the grid timed out.',
    );
  });

  it('keeps the message of a known error as a second sentence', () => {
    expect(sweepFailureSentence('192.0.2.46: ApiError: search_phase_execution_exception')).toBe(
      'The sweep could not read 192.0.2.46: the grid refused the query. The grid said: search_phase_execution_exception.',
    );
  });

  it('names a pass that is not an address', () => {
    expect(sweepFailureSentence('census page on hostname: ConnectionTimeout:')).toBe(
      'The sweep could not finish the census page on hostname: the grid timed out.',
    );
  });

  it('reads an IPv6 address whole', () => {
    expect(sweepFailureSentence('fd00::5: ConnectionError: refused')).toBe(
      'The sweep could not read fd00::5: the grid did not accept a connection. The grid said: refused.',
    );
  });

  it('says when an unknown error had no message', () => {
    expect(sweepFailureSentence('192.0.2.46: KeyError:')).toBe(
      'The sweep could not read 192.0.2.46. The error had no message.',
    );
  });

  it('leaves a string of another shape as it is', () => {
    // NEGATIVE CONTROL: a free sentence is not parsed into a wrong one.
    expect(sweepFailureSentence('census pass: ConnectionError querying logs-*')).toBe(
      'census pass: ConnectionError querying logs-*',
    );
    expect(sweepFailureSentence('')).toBe('');
  });

  it('still reads the errors list defensively', () => {
    expect(sweepErrorList({ errors: ['a', 3, 'b'] })).toEqual(['a', 'b']);
  });
});
