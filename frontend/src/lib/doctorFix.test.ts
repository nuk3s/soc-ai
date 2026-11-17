import { describe, expect, it } from 'vitest';
import { doctorFix, hintCommands, hintDoc, hintSettings, rowsByGrade } from './doctorFix';
import { docUrl, releaseNotesUrl } from './docsSite';

describe('doctorFix', () => {
  it('reads the commands, the settings and the doc of a hint', () => {
    const hint =
      'Run `soc-ai blocklists refresh` to fetch the feeds. Set ABUSE_CH_AUTH_KEY. Or remove `feodo` from `blocklist_sources`. See docs/BLOCKLISTS.md.';
    expect(hintCommands(hint)).toEqual(['soc-ai blocklists refresh']);
    expect(hintSettings(hint)).toEqual(['abuse_ch_auth_key']);
    expect(hintDoc(hint)).toEqual({ href: 'https://nuk3s.github.io/soc-ai/BLOCKLISTS/', label: 'docs/BLOCKLISTS.md' });
  });

  it('links a named section and skips a numbered part', () => {
    expect(hintDoc('See docs/DOCKER.md, TLS.')?.href).toBe('https://nuk3s.github.io/soc-ai/DOCKER/#tls');
    expect(hintDoc('See docs/SECURITY-ONION-SETUP.md, section 3.')?.href).toBe(
      'https://nuk3s.github.io/soc-ai/SECURITY-ONION-SETUP/',
    );
  });

  it('gives a PASS row no fix and a WARN row with no hint an empty fix', () => {
    // NEGATIVE CONTROL: a word in capitals is no setting, and a value span is no command.
    expect(doctorFix({ name: 'x', status: 'PASS', detail: '', hint: 'Set ES_PASSWORD.' })).toBeNull();
    expect(hintSettings('The TLS check and the URL of `ES_HOSTS` read OK.')).toEqual([]);
    expect(hintCommands('Remove `tor` from `blocklist_sources`.')).toEqual([]);
  });

  it('orders FAIL, then WARN, then the rest as the doctor wrote them', () => {
    const rows = ['PASS', 'WARN', 'INFO', 'FAIL', 'WARN'].map((status, i) => ({
      name: `r${i}`,
      status,
      detail: '',
      hint: '',
    }));
    expect(rowsByGrade(rows).map((r) => r.name)).toEqual(['r3', 'r1', 'r4', 'r0', 'r2']);
  });
});

describe('docsSite', () => {
  it('maps a repository doc and a version to the docs site', () => {
    expect(docUrl('docs/WEBUI_GUIDE.md')).toBe('https://nuk3s.github.io/soc-ai/WEBUI_GUIDE/');
    expect(releaseNotesUrl('1.6.0')).toBe('https://nuk3s.github.io/soc-ai/releases/1.6.0/');
    expect(releaseNotesUrl('v1.6.0+g1d7bb62')).toBe('https://nuk3s.github.io/soc-ai/releases/1.6.0/');
    expect(releaseNotesUrl(null)).toBe('https://nuk3s.github.io/soc-ai/project/changelog/');
  });
});
