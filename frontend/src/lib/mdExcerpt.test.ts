// Runbook list excerpts showed raw markdown ("# TLS and certificate anomaly
// triage … the *metadata* of encrypted sessions") — a 2-line clamp is no place
// to RENDER markdown, so strip the syntax for plain-text excerpts instead.
import { describe, expect, it } from 'vitest';
import { mdToPlainExcerpt } from './mdExcerpt';

describe('mdToPlainExcerpt', () => {
  it('strips headings, emphasis, and inline code', () => {
    expect(
      mdToPlainExcerpt('# TLS triage\nTLS alerts fire on the *metadata* of `encrypted` sessions.'),
    ).toBe('TLS triage TLS alerts fire on the metadata of encrypted sessions.');
  });

  it('unwraps links and list markers', () => {
    expect(mdToPlainExcerpt('- see [the docs](https://x.test/docs)\n- **bold** step')).toBe(
      'see the docs bold step',
    );
  });

  it('drops code fences but keeps their content', () => {
    expect(mdToPlainExcerpt('```oql\nevent.dataset:zeek.dns\n```\nThen pivot.')).toBe(
      'event.dataset:zeek.dns Then pivot.',
    );
  });

  it('collapses whitespace and trims', () => {
    expect(mdToPlainExcerpt('  a\n\n\nb  ')).toBe('a b');
  });
});
