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

// Dogfood 2026-10-19 (R5-D15): the excerpt of a runbook read "mpam-dbd.exe"
// for the file name "mpam-d_bd_*.exe". The strip removed every underscore and
// asterisk. Only a real emphasis marker goes; a literal one stays as written.
describe('mdToPlainExcerpt keeps literal markers', () => {
  it('keeps underscores and an asterisk inside a word', () => {
    expect(mdToPlainExcerpt('The file name is mpam-d_bd_*.exe.')).toBe(
      'The file name is mpam-d_bd_*.exe.',
    );
  });

  it('keeps snake_case names and a glob', () => {
    expect(mdToPlainExcerpt('Check user_agent_string and /var/log/*.log here.')).toBe(
      'Check user_agent_string and /var/log/*.log here.',
    );
  });

  it('keeps the text of inline code as written', () => {
    expect(mdToPlainExcerpt('Run `grep -r a_b*c` on the host.')).toBe(
      'Run grep -r a_b*c on the host.',
    );
  });

  it('turns an escaped marker into the literal character', () => {
    expect(mdToPlainExcerpt('Match \\*.exe and \\_tmp files.')).toBe(
      'Match *.exe and _tmp files.',
    );
  });

  it('keeps a lone asterisk and a lone tilde', () => {
    expect(mdToPlainExcerpt('Ports 1-1024 * 2 hosts in ~/logs.')).toBe(
      'Ports 1-1024 * 2 hosts in ~/logs.',
    );
  });

  // The control: real emphasis still goes, or the fix is "strip nothing".
  it('still strips real emphasis of each type', () => {
    expect(
      mdToPlainExcerpt('A *soft* and _soft_ and **hard** and __hard__ and ~~gone~~ word.'),
    ).toBe('A soft and soft and hard and hard and gone word.');
  });
});
