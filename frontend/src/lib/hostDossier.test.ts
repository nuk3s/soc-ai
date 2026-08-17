// The words the host pages say, tested as functions.
//
// The 2026-08-08 dogfood pass found the host screens rendering the data model
// instead of answering the analyst's question: raw field keys on screen, rung
// names as chips, and the one sentence the page exists for — "what is this
// machine, and why should I care" — never composed at all. This module is where
// that sentence and the plain-language vocabulary live, and these tests pin the
// composition RULES, not markup: which fields make the sentence, in what order,
// and what the page claims when an ingredient is missing.
import { describe, expect, it } from 'vitest';
import type { DossierFieldBrief, DossierFieldName } from './types';
import {
  activityProfileView,
  fieldLabel,
  fmtBytes,
  identitySentence,
  partitionFields,
  portStrings,
  portsView,
  provenancePhrase,
  relativeAge,
  roleLabel,
  ROLE_VOCABULARY,
  roleVocabulary,
  sentenceText,
  unresolvedPhrase,
} from './hostDossier';

const FIELDS: DossierFieldName[] = [
  'hostname',
  'mac',
  'os_family',
  'os_detail',
  'role',
  'services_offered',
  'management_plane',
  'domain_membership',
  'is_static_addressed',
  'activity_profile',
  'criticality',
  'policy_notes',
];

const brief = (field: DossierFieldName, over: Partial<DossierFieldBrief> = {}): DossierFieldBrief => ({
  field,
  value: null,
  value_json: null,
  source: null,
  confidence: 0,
  strength: 'none',
  reason: 'no_signal',
  overridden: false,
  conflict_kind: null,
  ...over,
});

/** A minimal host: all twelve fields unresolved, patched by name. */
const host = (
  patch: Partial<Record<DossierFieldName, Partial<DossierFieldBrief>>> = {},
  ip = '192.0.2.44',
) => ({
  ip,
  fields: FIELDS.map((f) => brief(f, patch[f] ?? {})),
});

/** Shorthand: a field that resolved to a scalar. */
const val = (value: string, over: Partial<DossierFieldBrief> = {}): Partial<DossierFieldBrief> => ({
  value,
  reason: null,
  source: 'behaviour',
  confidence: 0.9,
  strength: 'strong',
  ...over,
});

describe('identitySentence — the composed answer to "what is this machine?"', () => {
  it('assembles every known identity fact into one sentence, in reading order', () => {
    const parts = identitySentence(
      host({
        hostname: val('blue'),
        role: val('hypervisor'),
        os_family: val('linux'),
        os_detail: val('Proxmox VE 8.4 (Debian 12)'),
        domain_membership: val('CORP'),
        is_static_addressed: val('yes'),
        management_plane: { ...val('yes'), value_json: [8006, 22] },
      }),
    );
    expect(sentenceText(parts)).toBe(
      'blue is a hypervisor running Proxmox VE 8.4 (Debian 12), joined to CORP, ' +
        'at a fixed address, with admin interfaces on tcp/8006, tcp/22.',
    );
    // The nouns are bold; the connective tissue is not.
    const strong = parts.filter((p) => p.strong).map((p) => p.text);
    expect(strong).toContain('blue');
    expect(strong).toContain('hypervisor');
    expect(strong).toContain('Proxmox VE 8.4 (Debian 12)');
    expect(strong).toContain('tcp/8006, tcp/22');
    expect(strong).not.toContain(' is a ');
  });

  it('leads with the address when nothing has named the host', () => {
    const parts = identitySentence(host({ role: val('workstation') }));
    expect(sentenceText(parts)).toBe('192.0.2.44 is a workstation.');
    expect(parts[0]).toEqual({ text: '192.0.2.44', strong: true });
  });

  it('says honestly when nothing at all is known', () => {
    expect(sentenceText(identitySentence(host()))).toBe(
      '192.0.2.44 has been seen on the network, but nothing else is known about it yet.',
    );
  });

  it('still forms a sentence when the role is missing but other facts are not', () => {
    expect(sentenceText(identitySentence(host({ os_family: val('linux') })))).toBe(
      '192.0.2.44 is a machine running linux.',
    );
  });

  it('treats a role of "unknown" as unclassified, not as a kind of machine', () => {
    // "x is an unknown" would be the classifier's shrug read out as a noun.
    expect(sentenceText(identitySentence(host({ role: val('unknown') })))).toBe(
      '192.0.2.44 has been seen on the network, but nothing else is known about it yet.',
    );
  });

  it('prefers the specific OS to the family when both resolved', () => {
    const text = sentenceText(
      identitySentence(host({ os_family: val('linux'), os_detail: val('Ubuntu 24.04') })),
    );
    expect(text).toContain('running Ubuntu 24.04');
    expect(text).not.toContain('linux');
  });

  it('uses the right article for a vowel-led role', () => {
    expect(sentenceText(identitySentence(host({ role: val('iot') })))).toBe(
      '192.0.2.44 is an IoT device.',
    );
  });

  it('reads a DHCP answer as DHCP, not as the absence of a fact', () => {
    expect(sentenceText(identitySentence(host({ is_static_addressed: val('no') })))).toContain(
      'on a DHCP-assigned address',
    );
  });

  it('claims no admin interface when the sweep concluded "no"', () => {
    const text = sentenceText(
      identitySentence(host({ management_plane: { ...val('no'), value_json: [] } })),
    );
    expect(text).not.toContain('admin');
  });

  it('never reads an unresolved field into the sentence', () => {
    // A low-confidence lean is exactly what must NOT be asserted as identity.
    const text = sentenceText(
      identitySentence(host({ role: { value: null, reason: 'low_confidence' } })),
    );
    expect(text).not.toContain('null');
    expect(text).toContain('nothing else is known');
  });
});

describe('roleLabel', () => {
  it('spells the classifier vocabulary the way an analyst would', () => {
    expect(roleLabel('domain_controller')).toBe('domain controller');
    expect(roleLabel('security_appliance')).toBe('security appliance');
    expect(roleLabel('iot')).toBe('IoT device');
    expect(roleLabel('hypervisor')).toBe('hypervisor');
  });
  it('passes an operator-declared role through with underscores unfolded', () => {
    expect(roleLabel('build_farm')).toBe('build farm');
  });
});

describe('roleVocabulary — the wire list, with the frontend list as fallback', () => {
  it('prefers the server vocabulary when one arrived', () => {
    // A role the frontend fallback does not know: proof the wire wins so a new
    // backend role reaches the filter and the datalist without a frontend edit.
    const wire = ['workstation', 'printer'];
    expect(roleVocabulary(wire)).toBe(wire);
    expect(roleVocabulary(wire)).toContain('printer');
  });

  it('falls back to ROLE_VOCABULARY when the wire is missing or empty', () => {
    expect(roleVocabulary(undefined)).toBe(ROLE_VOCABULARY);
    expect(roleVocabulary(null)).toBe(ROLE_VOCABULARY);
    expect(roleVocabulary([])).toBe(ROLE_VOCABULARY);
  });
});

describe('provenancePhrase — where a fact came from, in words', () => {
  it('names the operator on a declared value', () => {
    expect(
      provenancePhrase({ overridden: true, source: 'operator', operator_actor: 'ops-lead' }),
    ).toBe('declared by ops-lead');
    expect(provenancePhrase({ overridden: true, source: 'operator', operator_actor: null })).toBe(
      'declared by an operator',
    );
  });
  it('translates each rung out of the storage vocabulary', () => {
    expect(provenancePhrase({ overridden: false, source: 'hostlog' })).toBe(
      'reported by the agent on the box',
    );
    expect(provenancePhrase({ overridden: false, source: 'osquery' })).toBe(
      'reported by the agent on the box',
    );
    expect(provenancePhrase({ overridden: false, source: 'telemetry' })).toBe(
      'seen in DNS/DHCP traffic',
    );
    expect(provenancePhrase({ overridden: false, source: 'banner' })).toBe(
      'read from a service banner',
    );
    expect(provenancePhrase({ overridden: false, source: 'behaviour' })).toBe(
      'inferred from its traffic',
    );
  });
  it('claims nothing for a rung it has not been taught', () => {
    expect(provenancePhrase({ overridden: false, source: 'seance' as never })).toBe('');
  });
});

describe('unresolvedPhrase — why a field is unknown, without blaming machinery', () => {
  it('distinguishes "not checked yet" from "checked, found nothing"', () => {
    expect(unresolvedPhrase({ reason: 'no_signal', last_run_at: null, retracted_at: null })).toBe(
      'not checked yet',
    );
    expect(
      unresolvedPhrase({ reason: 'no_signal', last_run_at: '2026-08-07T06:00:00Z', retracted_at: null }),
    ).toBe('checked — nothing found');
  });
  it('says a stale fact is old, not absent', () => {
    expect(
      unresolvedPhrase({ reason: 'stale', last_run_at: '2026-08-01T06:00:00Z', retracted_at: null }),
    ).toMatch(/too old to trust/i);
  });
  it('shows the lean behind a low-confidence withhold', () => {
    expect(
      unresolvedPhrase({
        reason: 'low_confidence',
        last_run_at: '2026-08-07T06:00:00Z',
        retracted_at: null,
        inferred_value: 'server',
      }),
    ).toBe('possibly "server", but the evidence is too thin to say');
  });
  it('says when the evidence behind a fact went away', () => {
    expect(
      unresolvedPhrase({ reason: 'no_signal', last_run_at: '2026-08-07T06:00:00Z', retracted_at: '2026-08-05T06:00:00Z' }),
    ).toMatch(/went away/i);
  });
});

describe('partitionFields', () => {
  it('splits resolved facts from unknowns, keeping wire order', () => {
    const d = host({ role: val('server'), hostname: val('web-01') });
    const { known, unknown } = partitionFields(d.fields);
    expect(known.map((f) => f.field)).toEqual(['hostname', 'role']);
    expect(unknown.length).toBe(10);
  });
  it('counts a structured value with a null scalar as known', () => {
    const d = host({
      services_offered: { value: null, value_json: [{ port: 22, proto: 'tcp' }], reason: null },
    });
    expect(partitionFields(d.fields).known.map((f) => f.field)).toEqual(['services_offered']);
  });
});

describe('fieldLabel', () => {
  it('never shows a schema key', () => {
    expect(fieldLabel('os_family')).toBe('Operating system');
    expect(fieldLabel('is_static_addressed')).toBe('Addressing');
    expect(fieldLabel('management_plane')).toBe('Admin interfaces');
    expect(fieldLabel('activity_profile')).toBe('Traffic pattern');
    expect(fieldLabel('policy_notes')).toBe('Operator note');
  });
});

describe('fmtBytes', () => {
  it('prints byte counts with units a reader can compare', () => {
    expect(fmtBytes(512)).toBe('512 B');
    expect(fmtBytes(1420)).toBe('1.4 KB');
    expect(fmtBytes(88132)).toBe('86 KB');
    expect(fmtBytes(912456)).toBe('891 KB');
    expect(fmtBytes(3_400_000)).toBe('3.2 MB');
  });
});

describe('portStrings', () => {
  it('spells bare numbers, port objects and strings the house way', () => {
    expect(portStrings([8006, 22])).toEqual(['tcp/8006', 'tcp/22']);
    expect(portStrings([{ port: 443, proto: 'tcp' }])).toEqual(['tcp/443']);
    expect(portStrings(['tcp/22'])).toEqual(['tcp/22']);
    expect(portStrings('not-a-list')).toEqual([]);
  });
});

describe('portsView — the admin/services payload in any of its wire shapes', () => {
  it('reads the {answers, ports} dict the live wire actually carries', () => {
    // Confirmed off a running instance (2026-08-09 dogfood): management_plane
    // arrived as {'answers': True, 'ports': [8006, 8007, 22]} with the scalar
    // null — not the bare list the renderer and the sentence composer were
    // built against. value_json is open-shaped on the wire; the normalizer,
    // not each consumer, absorbs that.
    const view = portsView({ answers: true, ports: [8006, 8007, 22] });
    expect(view).toEqual({ answers: true, ports: ['tcp/8006', 'tcp/8007', 'tcp/22'] });
  });
  it('keeps an explicit "no" an explicit no', () => {
    expect(portsView({ answers: false, ports: [] })).toEqual({ answers: false, ports: [] });
  });
  it('reads the builder`s bare list without inventing an answers claim', () => {
    expect(portsView([8006, 22])).toEqual({ answers: null, ports: ['tcp/8006', 'tcp/22'] });
    expect(portsView([])).toEqual({ answers: null, ports: [] });
  });
  it('refuses a shape that is not ports at all', () => {
    expect(portsView('tcp/22')).toBeNull();
    expect(portsView({ hour_of_day: {} })).toBeNull();
    expect(portsView(null)).toBeNull();
  });
});

describe('identitySentence — the admin clause fires on the real payload', () => {
  it('says the thing the incident was about: a hypervisor with its management plane exposed', () => {
    // The sparse-shape composer looked for value === "yes" — which the live
    // payload does not carry — so the one clause the feature exists for
    // silently dropped out of the sentence.
    const text = sentenceText(
      identitySentence(
        host({
          role: val('hypervisor'),
          management_plane: {
            value: null,
            value_json: { answers: true, ports: [8006, 8007, 22] },
            reason: null,
          },
        }),
      ),
    );
    expect(text).toBe(
      '192.0.2.44 is a hypervisor with admin interfaces on tcp/8006, tcp/8007, tcp/22.',
    );
  });

  it('claims nothing when the payload answers "no"', () => {
    const text = sentenceText(
      identitySentence(
        host({
          management_plane: { value: null, value_json: { answers: false, ports: [] }, reason: null },
        }),
      ),
    );
    expect(text).not.toContain('admin');
  });
});

describe('activityProfileView — the JSON histogram as something readable', () => {
  const payload = {
    hour_of_day: { '0': 120, '2': 200, '14': 191, '23': 50 },
    busiest_hours: [2, 14, 0],
    orig_bytes_p50: 1420,
    orig_bytes_p95: 88132,
    resp_bytes_p50: 5120,
    resp_bytes_p95: 912456,
    distinct_ja3: 4,
    initiates_remote_access: false,
    remote_access_ports: [],
  };

  it('turns the histogram object into 24 ordered buckets', () => {
    const view = activityProfileView(payload);
    expect(view?.hours.length).toBe(24);
    expect(view?.hours[2]).toBe(200);
    expect(view?.hours[1]).toBe(0); // a missing hour is quiet, not absent
  });

  it('states the byte shape in words with units, not raw JSON keys', () => {
    const lines = activityProfileView(payload)?.lines.join(' · ') ?? '';
    expect(lines).toContain('typical request 1.4 KB');
    expect(lines).toContain('typical response 5 KB');
    expect(lines).toContain('4 distinct TLS fingerprints');
    expect(lines).not.toContain('p95');
    expect(lines).not.toContain('orig_bytes');
  });

  it('calls out outbound remote access when the host initiates it', () => {
    const view = activityProfileView({
      ...payload,
      initiates_remote_access: true,
      remote_access_ports: [3389],
    });
    expect(view?.lines.join(' ')).toContain('initiates outbound remote access on tcp/3389');
  });

  it('returns null for a payload that is not the profile shape', () => {
    expect(activityProfileView(null)).toBeNull();
    expect(activityProfileView([1, 2, 3])).toBeNull();
  });
});

describe('relativeAge — freshness a reader can feel', () => {
  const now = Date.parse('2026-08-08T12:00:00Z');
  it('reads in minutes, hours, days, months and years', () => {
    expect(relativeAge('2026-08-08T11:58:00Z', now)).toBe('2m ago');
    expect(relativeAge('2026-08-08T03:00:00Z', now)).toBe('9h ago');
    expect(relativeAge('2026-08-01T12:00:00Z', now)).toBe('7d ago');
    expect(relativeAge('2025-07-01T12:00:00Z', now)).toBe('13mo ago');
    expect(relativeAge('2023-08-08T12:00:00Z', now)).toBe('3y ago');
  });
  it('says never for a thing that has not happened', () => {
    expect(relativeAge(null, now)).toBe('never');
  });
});
