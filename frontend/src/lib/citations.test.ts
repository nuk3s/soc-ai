// A cited field in words (review 2026-11-12, console finding 6). The chips
// printed "alert.payload_printable" and "community_id_events.0.zeek_http_status".
import { describe, expect, it } from 'vitest';
import { fieldChipLabel, fieldChipTitle, fieldWords, findingCitation } from './citations';

describe('fieldChipLabel', () => {
  it('names a field in words with a short value', () => {
    expect(fieldChipLabel('community_id_events.0.zeek_http_status', '200')).toBe('HTTP status 200');
    expect(fieldChipLabel('alert.rule_metadata.signature_severity', 'Informational')).toBe(
      'Rule metadata severity Informational',
    );
  });

  it('names the two severity fields apart, each with its source in the tooltip', () => {
    // Round 3 part 2, P4: a card showed "rule severity High" beside
    // "Signature severity Informational".
    expect(fieldChipLabel('alert.severity_label', 'High')).toBe('Alert severity High');
    expect(fieldChipTitle('alert.rule_metadata.signature_severity', { documentId: 'd1' })).toBe(
      'Field alert.rule_metadata.signature_severity. The author of the rule writes this level in the rule metadata. ' +
        'It can differ from the alert severity. Open the alert at this field.',
    );
    expect(fieldChipTitle('alert.severity_label', {})).toContain('Security Onion records this level on the alert.');
    // Negative control: a field with no note keeps the short tooltip.
    expect(fieldChipTitle('alert.payload_printable', { documentId: 'd1' })).toBe(
      'Field alert.payload_printable. Open the alert at this field.',
    );
  });

  it('drops a long value, a value of two lines and an object', () => {
    expect(fieldChipLabel('alert.payload_printable', 'POST /index.php HTTP/1.1\r\nHost: x')).toBe('Payload');
    expect(fieldChipLabel('alert.rule_name', 'ET EXPLOIT PHP php2shell Multipart Header Amplification')).toBe(
      'Rule name',
    );
    expect(fieldChipLabel('host_alert_profiles.0.as_source', '{"ET X":3}')).toBe('Alerts as source');
  });

  it('reads an unknown leaf as its words', () => {
    expect(fieldWords('alert.zeek_smb_share_name')).toBe('Smb share name');
    expect(fieldChipLabel('alert.rule_metadata.metadata_tags', null)).toBe('Rule tags');
  });
});

describe('fieldChipTitle', () => {
  it('keeps the raw path and names the document it opens', () => {
    expect(fieldChipTitle('community_id_events.1.zeek_http_status', { documentId: 'd1', value: '200' })).toBe(
      'Field community_id_events.1.zeek_http_status. Open session event 2 at this field.',
    );
    expect(fieldChipTitle('alert.payload_printable', { documentId: 'd1', value: 'x' })).toContain('Open the alert');
  });

  it('says why a chip opens nothing', () => {
    expect(fieldChipTitle('alert.alert.alert_action', {})).toBe(
      'Field alert.alert.alert_action. soc-ai cannot find this field in a stored document, so the chip opens nothing.',
    );
    expect(fieldChipTitle('host_coverage.0.coverage.planes', { value: '["network"]' })).toContain(
      'No grid document holds it',
    );
    expect(fieldChipTitle('alert.x', { documentId: 'd1', value: '1', resolved: false })).toContain(
      'did not resolve',
    );
  });
});

describe('findingCitation', () => {
  it('reads a tool result in words', () => {
    expect(findingCitation('t_rule_prevalence ET CINS Poor Reputation IP group 148')).toEqual({
      kind: 'text',
      label: 'Rule history: ET CINS Poor Reputation IP group 148',
      title: expect.stringContaining('t_rule_prevalence ET CINS'),
    });
    expect(findingCitation('t_enrich_ip 10.20.30.5')).toMatchObject({ label: 'Address look-up: 10.20.30.5' });
  });

  it('keeps a query and a flow id as plain chips', () => {
    expect(findingCitation('suricata.alert rule aggregation for source.ip 10.20.30.5')).toMatchObject({
      kind: 'text',
    });
    expect(findingCitation('1:xkXJsXeXObIQS70E1UFF7IgxyTU=')).toMatchObject({
      kind: 'text',
      label: 'Flow 1:xkXJsXeXObIQS70E1UFF7IgxyTU=',
    });
  });

  it('control: a document id stays a document', () => {
    expect(findingCitation('v08vkqEB6RQ6BUvoLzu6')).toEqual({ kind: 'document', id: 'v08vkqEB6RQ6BUvoLzu6' });
  });
});
