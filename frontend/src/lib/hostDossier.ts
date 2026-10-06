// ---------------------------------------------------------------------------
// The host pages' language, in one place.
//
// The dossier store speaks in schema keys, provenance rungs and confidence
// floats. The analyst reading a host page owns none of that vocabulary — and
// the 2026-08-08 dogfood pass showed what happens when the storage layer's
// words reach the screen: a page that "covers the schema and tells them how
// the resolver works". Everything here translates one into the other, so the
// two host screens (and only they) can speak analyst without each inventing
// its own dialect.
//
// Nothing in this file renders. It is pure functions over wire types, which is
// what lets the identity sentence's composition RULES be tested as rules.
// ---------------------------------------------------------------------------

import type {
  DossierFieldBrief,
  DossierFieldName,
  DossierField,
  MachineAddressKind,
  MachineNameSource,
  MachineRole,
  MachineRoleState,
} from './types';

// ---- field labels -----------------------------------------------------------

/** What each of the twelve fields is called on screen. Never the schema key:
 *  `is_static_addressed` is a column name, "Addressing" is a fact about a
 *  machine. The raw key survives only in URLs (?field=) and API calls. */
const FIELD_LABELS: Record<DossierFieldName, string> = {
  hostname: 'Hostname',
  mac: 'MAC address',
  os_family: 'Operating system',
  os_detail: 'OS version',
  role: 'Role',
  services_offered: 'Services offered',
  management_plane: 'Admin interfaces',
  domain_membership: 'Domain',
  is_static_addressed: 'Addressing',
  activity_profile: 'Traffic pattern',
  criticality: 'Criticality',
  policy_notes: 'Operator note',
};

export function fieldLabel(name: DossierFieldName): string {
  return FIELD_LABELS[name];
}

// ---- roles ------------------------------------------------------------------

/** The classifier vocabulary, spelled for reading. Everything else (operator
 *  free text) gets its underscores unfolded and is otherwise passed through —
 *  it is the operator's own word and not ours to rename. */
const ROLE_LABELS: Record<string, string> = {
  domain_controller: 'domain controller',
  security_appliance: 'security appliance',
  network_device: 'network device',
  iot: 'IoT device',
};

export function roleLabel(role: string): string {
  const key = role.trim().toLowerCase();
  return ROLE_LABELS[key] ?? role.trim().replace(/_/g, ' ');
}

/** The classifier's closed role vocabulary — the FALLBACK.
 *
 *  This list used to be the only copy, mirroring soc_ai/dossier/infer.py's
 *  scattered `_match_role` return literals with nothing but a comment linking
 *  the two: the moment the backend gained a role (`printer`, say), the filter
 *  and the declare form disagreed until this was hand-edited (the F10 finding —
 *  a filter that enumerated the vocabulary twelve pixels above a free-text input
 *  that did not offer it). The backend now owns the vocabulary as a real
 *  constant and ships it on `/dossiers/summary`; both consumers read it from the
 *  wire via {@link roleVocabulary}, and this stays as the fallback for an older
 *  server (or a test) that does not send it. */
export const ROLE_VOCABULARY: readonly string[] = [
  'domain_controller',
  'hypervisor',
  'iot',
  'network_device',
  'security_appliance',
  'server',
  'unknown',
  'workstation',
];

/** The role vocabulary to offer: the server's list when it sent one, else the
 *  {@link ROLE_VOCABULARY} fallback. One helper so the host filter and the
 *  declare datalist cannot disagree about where the vocabulary comes from — the
 *  whole point of moving the source behind the wire. */
export function roleVocabulary(wire?: readonly string[] | null): readonly string[] {
  return wire && wire.length > 0 ? wire : ROLE_VOCABULARY;
}

/** The three fields a scalar cannot carry: their operator lane is written
 *  through `value_json` with the scalar left null, so their editor is a
 *  validated JSON textarea rather than a text input. */
export const JSON_FIELDS: readonly DossierFieldName[] = [
  'services_offered',
  'activity_profile',
  'management_plane',
];

export const isJsonField = (name: DossierFieldName): boolean => JSON_FIELDS.indexOf(name) >= 0;

// ---- provenance -------------------------------------------------------------

/** Where a fact came from, in words a reader who never met the provenance
 *  ladder can weigh. The rung names themselves stay available inside the
 *  evidence drawer for whoever asks "says who, exactly?". */
const SOURCE_PHRASES: Record<string, string> = {
  hostlog: 'reported by the agent on the box',
  osquery: 'reported by the agent on the box',
  telemetry: 'seen in DNS/DHCP traffic',
  banner: 'read from a service banner',
  behaviour: 'inferred from its traffic',
};

export function provenancePhrase(f: {
  overridden: boolean;
  source: string | null;
  operator_actor?: string | null;
}): string {
  if (f.overridden) return `declared by ${f.operator_actor ?? 'an operator'}`;
  if (!f.source) return '';
  // An unknown rung claims nothing rather than guessing — the ladder is
  // server-side and can grow.
  return SOURCE_PHRASES[f.source.trim().toLowerCase()] ?? '';
}

// ---- unknowns ---------------------------------------------------------------

/** Why a field has no answer, in words that never contradict the header.
 *
 *  The store's `no_signal` covers two different truths — "no sweep has looked"
 *  and "a sweep looked and found nothing" — and the old copy ("No build has
 *  evaluated this field yet") asserted the first under a header proving the
 *  second. `last_run_at` is the discriminator the wire already carries. */
export function unresolvedPhrase(f: {
  reason: string | null;
  last_run_at: string | null;
  retracted_at: string | null;
  inferred_value?: string | null;
}): string {
  if (f.reason === 'stale') {
    return f.last_run_at
      ? `stale. The sweep last checked it ${relativeAge(f.last_run_at)}, too old to trust`
      : 'stale. Last seen too long ago, too old to trust';
  }
  if (f.reason === 'low_confidence') {
    return f.inferred_value && f.inferred_value.trim().toLowerCase() !== 'unknown'
      ? `low confidence: "${f.inferred_value}". The evidence is too thin to say`
      : 'a faint signal, too thin to say';
  }
  if (f.retracted_at) return 'the evidence behind it has gone';
  if (!f.last_run_at) return 'not checked yet';
  return 'checked, nothing found';
}

// ---- resolution -------------------------------------------------------------

/** Did this field resolve to an answer? `reason` is the backend's own "no"
 *  marker; a structured field carries its answer in `value_json` with the
 *  scalar left null, so both slots are read. */
export function isResolved(f: DossierFieldBrief): boolean {
  if (f.reason != null) return false;
  return (f.value != null && f.value.trim() !== '') || f.value_json != null;
}

/** A guess the resolver withheld, with the state that withheld it. */
export interface WithheldGuess {
  /** `low_confidence`: fresh, below the gate. `stale`: older than the window. */
  state: 'low_confidence' | 'stale';
  /** The sweep's guess, as stored. */
  value: string;
  /** For a stale guess, how long ago the sweep last checked it. */
  age: string | null;
}

/**
 * The sweep worked this field out and the resolver withheld the answer.
 *
 * The evidence failed the confidence gate, or the value went stale, and no
 * operator has declared anything over it. That is not "unknown": there IS a
 * guess, and on a role it is the difference between a host nothing can score
 * and a host nobody has looked at.
 *
 * Null when there is no guess to name: an override, a resolved field, no
 * inferred value, or the classifier's own "unknown". Every unknown row wore a
 * "possibly" chip whose tooltip claimed a withheld inference, and the wire
 * held none. Same rule as the summary's two withheld buckets
 * (store/host_dossier.py, _effective_role), and the server lists both.
 */
export function withheldGuess(f: DossierFieldBrief, now = Date.now()): WithheldGuess | null {
  if (f.overridden) return null;
  if (f.reason !== 'low_confidence' && f.reason !== 'stale') return null;
  const value = (f.inferred_value ?? '').trim();
  if (!value || value.toLowerCase() === 'unknown') return null;
  return {
    state: f.reason,
    value,
    age: f.reason === 'stale' && f.last_run_at ? relativeAge(f.last_run_at, now) : null,
  };
}

export function isWithheldGuess(f: DossierFieldBrief): boolean {
  return withheldGuess(f) != null;
}

/** The one phrase for a withheld guess: "server · low confidence" or
 *  "server · stale 8d ago". Labels, never slugs. */
export function withheldPhrase(g: WithheldGuess, label: (v: string) => string = roleLabel): string {
  return g.state === 'stale'
    ? `${label(g.value)} · stale${g.age ? ` ${g.age}` : ''}`
    : `${label(g.value)} · low confidence`;
}

/** A stored value in reading form: a role label, a port list, or the scalar. */
export function valueText(field: DossierFieldName, value: string | null, json: unknown): string | null {
  const scalar = (value ?? '').trim();
  if (scalar) return field === 'role' ? roleLabel(scalar) : scalar;
  if (json == null) return null;
  const ports = portsView(json);
  if (ports && ports.ports.length > 0) return ports.ports.join(', ');
  if (field === 'activity_profile') return 'a traffic pattern';
  return null;
}

/**
 * What removing a declaration leaves, in one sentence for the button.
 *
 * The old copy said "The sweep's answer domain_controller then stands" while
 * the field went to a low-confidence guess at 0.50, or to nothing at all.
 * This reads the lane underneath and states the real outcome, with the label.
 */
export function removeOutcome(f: DossierField): string {
  const text = valueText(f.field, f.inferred_value, f.inferred_value_json);
  const conf = f.inferred_confidence != null ? ` at ${f.inferred_confidence.toFixed(2)}` : '';
  const unknownGuess = f.field === 'role' && (f.inferred_value ?? '').trim().toLowerCase() === 'unknown';
  if (text == null || unknownGuess) {
    return 'Remove my declaration. This field then goes back to unknown.';
  }
  const reason = f.inference_reason === undefined ? null : f.inference_reason;
  if (reason === 'low_confidence') {
    return `Remove my declaration. The sweep's answer, ${text}${conf}, then shows as a low-confidence guess.`;
  }
  if (reason === 'stale') {
    return `Remove my declaration. The sweep's answer, ${text}, is stale and then shows as a stale guess.`;
  }
  if (reason === 'no_signal') {
    return 'Remove my declaration. This field then goes back to unknown.';
  }
  return `Remove my declaration. The sweep's answer, ${text}${conf}, then stands.`;
}

/** Wire order in, wire order out — the screens must not invent an ordering the
 *  investigation prompt does not share. */
export function partitionFields<T extends DossierFieldBrief>(
  fields: T[],
): { known: T[]; unknown: T[] } {
  const known: T[] = [];
  const unknown: T[] = [];
  for (const f of fields) (isResolved(f) ? known : unknown).push(f);
  return { known, unknown };
}

// ---- ports ------------------------------------------------------------------

/** One port entry the house way: "tcp/8006". The builder writes bare ints for
 *  management_plane and {port, proto, count, service} records for services;
 *  an operator override is free-form JSON — all three must survive. */
export function portString(entry: unknown): string {
  const rec = entry && typeof entry === 'object' ? (entry as Record<string, unknown>) : null;
  const port = rec ? rec.port : entry;
  if (typeof port === 'number') return `${(rec?.proto as string) ?? 'tcp'}/${port}`;
  if (typeof port === 'string') {
    // Already spelled ("tcp/22") — don't double the prefix.
    return port.includes('/') ? port : `${(rec?.proto as string) ?? 'tcp'}/${port}`;
  }
  return rec ? JSON.stringify(entry) : String(entry);
}

/** A port payload as strings, or [] when it is not a list at all. */
export function portStrings(payload: unknown): string[] {
  if (!Array.isArray(payload)) return [];
  return payload.map(portString);
}

/** What a ports-shaped payload actually says. */
export interface PortsView {
  /** The payload's own yes/no, when it carries one ({answers: bool, ports:
   *  [...]}). Null for the bare-list shape — a list does not answer the
   *  question, and inventing a claim it never made is how a renderer lies. */
  answers: boolean | null;
  /** Spelled the house way: "tcp/8006". */
  ports: string[];
}

/**
 * Normalize the admin-interface / services payload from ANY of the shapes the
 * wire carries. `value_json` is open-shaped: the builder writes a bare port
 * list, a running instance was observed serving `{"answers": true, "ports":
 * [8006, 8007, 22]}` with the scalar null (2026-08-09 dogfood), and an
 * operator override is free-form JSON. The first rebuild pass handled only
 * the list — and the dict rendered as raw JSON on the flagship host while the
 * identity sentence silently dropped its admin clause. One normalizer here,
 * so no consumer meets a shape alone again. Null when the payload is not
 * ports-shaped at all; callers fall back to the generic rendering.
 */
export function portsView(payload: unknown): PortsView | null {
  if (Array.isArray(payload)) {
    return { answers: null, ports: portStrings(payload) };
  }
  if (payload && typeof payload === 'object') {
    const rec = payload as Record<string, unknown>;
    if (Array.isArray(rec.ports)) {
      return {
        answers: typeof rec.answers === 'boolean' ? rec.answers : null,
        ports: portStrings(rec.ports),
      };
    }
  }
  return null;
}

// ---- bytes ------------------------------------------------------------------

/** Byte counts with units. "resp bytes p95 912456" was shipped unreadable;
 *  "891 KB" is the same fact at a glance. One decimal under 10, none above —
 *  false precision reads as meaning. */
export function fmtBytes(n: number): string {
  if (!Number.isFinite(n)) return '—';
  if (n < 1000) return `${Math.round(n)} B`;
  // "5.0 KB" is false precision wearing a decimal; "5 KB" is the same fact.
  const short = (x: number): string =>
    x < 10 ? x.toFixed(1).replace(/\.0$/, '') : String(Math.round(x));
  const kb = n / 1024;
  if (kb < 1000) return `${short(kb)} KB`;
  return `${short(kb / 1024)} MB`;
}

// ---- the activity profile ---------------------------------------------------

export interface ActivityProfileView {
  /** 24 buckets, hour 0..23, missing hours read as quiet. The one field that
   *  wants a sparkline instead of `{"0":120,...}` on screen. */
  hours: number[];
  /** The rest of the payload as readable statements, in reading order. */
  lines: string[];
}

/** The builder's activity payload (infer._infer_activity_profile) rendered
 *  into chartable buckets and sentences. Null when the payload is not that
 *  shape — an operator can override this field with anything, and a foreign
 *  shape falls back to the generic structured rendering rather than a wrong
 *  chart. */
export function activityProfileView(payload: unknown, scalar?: string | null): ActivityProfileView | null {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) return null;
  const rec = payload as Record<string, unknown>;
  const histogram = rec.hour_of_day;
  if (!histogram || typeof histogram !== 'object' || Array.isArray(histogram)) return null;

  const hours: number[] = [];
  for (let h = 0; h < 24; h += 1) {
    const raw = (histogram as Record<string, unknown>)[String(h)];
    hours.push(typeof raw === 'number' && Number.isFinite(raw) ? raw : 0);
  }

  const lines: string[] = [];
  const num = (key: string): number | null =>
    typeof rec[key] === 'number' && Number.isFinite(rec[key] as number)
      ? (rec[key] as number)
      : null;

  const reqTypical = num('orig_bytes_p50');
  const reqLarge = num('orig_bytes_p95');
  if (reqTypical != null) {
    lines.push(
      `typical request ${fmtBytes(reqTypical)}` +
        (reqLarge != null ? `, up to ${fmtBytes(reqLarge)}` : ''),
    );
  }
  const respTypical = num('resp_bytes_p50');
  const respLarge = num('resp_bytes_p95');
  if (respTypical != null) {
    lines.push(
      `typical response ${fmtBytes(respTypical)}` +
        (respLarge != null ? `, up to ${fmtBytes(respLarge)}` : ''),
    );
  }
  const ja3 = num('distinct_ja3');
  if (ja3 != null) lines.push(`${ja3} distinct TLS fingerprints`);
  // Only the positive is worth a line: the scalar summary above the chart
  // already says "no outbound remote access", and repeating a negative is how
  // the old page said everything twice.
  // The fact's own sentence (rendered directly above these lines) already ends
  // "initiates remote access on tcp/22, tcp/5985" when it is true, so the same
  // clause appeared twice on the DC's page, one line apart. Say it once.
  const scalarSaysSo = /initiates (outbound )?remote access/i.test(scalar ?? '');
  if (rec.initiates_remote_access === true && !scalarSaysSo) {
    const ports = portStrings(rec.remote_access_ports);
    lines.push(
      ports.length > 0
        ? `initiates outbound remote access on ${ports.join(', ')}`
        : 'initiates outbound remote access',
    );
  }
  return { hours, lines };
}

// ---- freshness --------------------------------------------------------------

/** Relative age with a range wide enough for a dossier: `ago()` in
 *  lib/timeRange tops out at days, which renders "first seen 395d ago" for a
 *  host the operator thinks of as "a year old". Absolute stamps belong in
 *  tooltips and the evidence drawer, not headers. */
export function relativeAge(iso: string | null | undefined, now = Date.now()): string {
  if (!iso) return 'never';
  const ms = now - new Date(iso).getTime();
  if (!Number.isFinite(ms)) return '—';
  if (ms < 60_000) return 'now';
  const minutes = ms / 60_000;
  if (minutes < 60) return `${Math.round(minutes)}m ago`;
  const hours = minutes / 60;
  if (hours < 48) return `${Math.round(hours)}h ago`;
  const days = hours / 24;
  if (days < 60) return `${Math.round(days)}d ago`;
  const months = days / 30.44;
  if (months < 24) return `${Math.round(months)}mo ago`;
  return `${Math.round(days / 365.25)}y ago`;
}

// ---- the identity sentence --------------------------------------------------

export interface SentencePart {
  text: string;
  /** Bold the nouns, not the chips: the subject and each fact's payload are
   *  strong, the connective tissue never is. */
  strong?: boolean;
}

export const sentenceText = (parts: SentencePart[]): string =>
  parts.map((p) => p.text).join('');

/** One field of a row, by name. */
function fieldOf(
  fields: DossierFieldBrief[],
  name: DossierFieldName,
): DossierFieldBrief | undefined {
  return fields.find((f) => f.field === name);
}

/** A field's resolved scalar, or null. Exported: the palette's host results
 *  (CommandPalette.tsx) read hostname/role off a DossierRow the same way the
 *  identity sentence does — one extractor, not a second one re-deriving the
 *  same "resolved and non-blank" rule. */
export function scalarOf(fields: DossierFieldBrief[], name: DossierFieldName): string | null {
  const f = fieldOf(fields, name);
  if (!f || !isResolved(f)) return null;
  const v = (f.value ?? '').trim();
  return v.length > 0 ? v : null;
}

const startsWithVowel = (word: string): boolean => /^[aeiou]/i.test(word);

// os_family is internal vocabulary (soc_ai/dossier/infer.py:_HOSTLOG_OS_FAMILY)
// — "apple" covers macOS/iOS/Darwin. Display labels for the sentence; a family
// this map does not know falls through verbatim rather than hiding the field.
const OS_FAMILY_LABELS: Record<string, string> = {
  apple: 'an Apple OS',
  linux: 'Linux',
  windows: 'Windows',
  android: 'Android',
  freebsd: 'FreeBSD',
};

/**
 * The one sentence the page exists for: what this machine IS, composed from
 * every resolved identity fact, declared values winning (they already won at
 * resolve time — this reads the resolver's output and composes, never decides).
 *
 * Composition rules, in order:
 *   subject  — hostname if resolved, else the address. Always bold.
 *   role     — "is a|an <role>" (bold), skipped when unresolved or the
 *              classifier's own "unknown"; when other clauses exist without a
 *              role, "is a machine" carries the verb instead.
 *   os       — "running <os_detail ?? os_family>" (bold).
 *   domain   — "joined to <domain>" (bold).
 *   address  — "at a fixed address" / "on a DHCP-assigned address".
 *   admin    — "with admin interfaces on <tcp/8006, tcp/22>" (ports bold),
 *              only when management_plane resolved "yes" with ports.
 *   nothing  — "<subject> has been seen on the network, but nothing else is
 *              known about it yet."
 *
 * Criticality and the policy note are deliberately NOT here: they are why-care,
 * not identity, and the strip directly below carries them with their author.
 * Saying "critical" in both places would restate one fact 40px apart — the
 * exact duplication the 2026-08-08 pass counted six deep on conflicts.
 */
export function identitySentence(
  host: {
    ip: string;
    fields: DossierFieldBrief[];
  },
  // The machine name, when the page is a machine page. The machine name comes
  // from the strongest source on any address; the primary address's own
  // hostname field may be empty while the agent names the box.
  name?: string | null,
): SentencePart[] {
  const { fields } = host;
  const subject = (name ?? '').trim() || scalarOf(fields, 'hostname') || host.ip;
  const parts: SentencePart[] = [{ text: subject, strong: true }];

  type Clause = SentencePart[];
  const clauses: Clause[] = [];

  const rawRole = scalarOf(fields, 'role');
  const role = rawRole && rawRole.toLowerCase() !== 'unknown' ? roleLabel(rawRole) : null;
  if (role) {
    clauses.push([
      { text: `is ${startsWithVowel(role) ? 'an' : 'a'} ` },
      { text: role, strong: true },
    ]);
  }

  const osDetail = scalarOf(fields, 'os_detail');
  const osFamily = scalarOf(fields, 'os_family');
  const os = osDetail ?? (osFamily ? OS_FAMILY_LABELS[osFamily.toLowerCase()] ?? osFamily : null);
  if (os) clauses.push([{ text: 'running ' }, { text: os, strong: true }]);

  const domain = scalarOf(fields, 'domain_membership');
  if (domain) clauses.push([{ text: 'joined to ' }, { text: domain, strong: true }]);

  const addressing = scalarOf(fields, 'is_static_addressed');
  if (addressing === 'yes') clauses.push([{ text: 'at a fixed address' }]);
  else if (addressing === 'no') clauses.push([{ text: 'on a DHCP-assigned address' }]);

  // The clause the original incident was about — a machine with its
  // management plane exposed. Read through portsView, not the scalar: the
  // live wire carries {answers, ports} with the scalar null, and matching
  // only value === "yes" silently dropped this clause from the one sentence
  // that needed it.
  const mgmt = fieldOf(fields, 'management_plane');
  if (mgmt && isResolved(mgmt)) {
    const view = portsView(mgmt.value_json);
    const denied = (mgmt.value ?? '').trim().toLowerCase() === 'no' || view?.answers === false;
    if (!denied && view != null && view.ports.length > 0) {
      clauses.push([
        { text: 'with admin interfaces on ' },
        { text: view.ports.join(', '), strong: true },
      ]);
    }
  }

  if (clauses.length === 0) {
    parts.push({ text: ' has appeared on the network. Nothing else is known about it yet.' });
    return parts;
  }

  // A sentence with facts but no role still needs its verb.
  if (!role) clauses.unshift([{ text: 'is a machine' }]);

  // "is a hypervisor running Proxmox, joined to CORP, at a fixed address" —
  // the verb clause and its first fact read as one breath; commas start after.
  clauses.forEach((clause, i) => {
    parts.push({ text: i <= 1 ? ' ' : ', ' });
    parts.push(...clause);
  });
  parts.push({ text: '.' });
  return parts;
}

// ---- coverage ---------------------------------------------------------------

/** The two rungs that only exist because something ON the machine reported
 *  (soc_ai/dossier/types.py calls hostlog "what an agent on the host
 *  reported"). Read from BOTH lanes: an operator typing a hostname does not
 *  uninstall the agent, so the inference lane — which survives an override —
 *  counts too. */
const SELF_REPORTED = new Set(['hostlog', 'osquery']);

export function selfReportedFields(fields: DossierField[]): DossierFieldName[] {
  return fields
    .filter((f) => {
      const rungs = [
        ...(f.inferred_source ? [f.inferred_source] : []),
        ...(f.reason == null && f.source ? [f.source] : []),
      ];
      return rungs.some((rung) => SELF_REPORTED.has(rung));
    })
    .map((f) => f.field);
}

// ---- machines ---------------------------------------------------------------
//
// A machine is a set of addresses soc-ai holds to be one device. The server
// resolves its name, its role and the state of that role; these helpers only
// put the answer into words.

/** A machine key as the API spells it: `agent:<id>`, `mac:<mac>`, `ip:<address>`.
 *  No address and no host name starts with one of these prefixes. */
export function isMachineKey(value: string): boolean {
  return /^(agent|mac|ip):./.test(value.trim());
}

const NAME_SOURCE_LABELS: Record<MachineNameSource, string> = {
  declared: 'declared',
  agent: 'agent',
  dhcp: 'DHCP lease',
  dns: 'DNS',
  ntlm: 'NTLM',
  other: 'other source',
};

/** The small text under a machine name: where the name came from. */
export function nameSourceLabel(source: string | null | undefined): string | null {
  if (!source) return null;
  return NAME_SOURCE_LABELS[source as MachineNameSource] ?? source;
}

const NAME_SOURCE_TITLES: Record<MachineNameSource, string> = {
  declared: 'An operator declared this name.',
  agent: 'The agent on the machine reports this name.',
  dhcp: 'A DHCP lease for this machine carries this name.',
  dns: 'A DNS answer for the primary address carries this name.',
  ntlm: 'An NTLM logon from this machine carries this name.',
  other: 'Other network evidence carries this name.',
};

export function nameSourceTitle(source: string | null | undefined): string | undefined {
  if (!source) return undefined;
  return NAME_SOURCE_TITLES[source as MachineNameSource];
}

const ADDRESS_KIND_LABELS: Record<MachineAddressKind, string> = {
  agent: 'agent',
  dhcp: 'DHCP lease',
  name: 'DNS name',
  network: 'network',
};

const ADDRESS_KIND_TITLES: Record<MachineAddressKind, string> = {
  agent: 'The agent on the machine reports this address.',
  dhcp: 'A DHCP lease gave this address to a MAC of this machine.',
  name: 'The DNS name of this address matches the machine name.',
  network: 'Only network traffic ties this address to the machine.',
};

/** How soc-ai tied an address to its machine, in words. */
export function addressKindLabel(kind: string): string {
  return ADDRESS_KIND_LABELS[kind as MachineAddressKind] ?? kind;
}

export function addressKindTitle(kind: string): string | undefined {
  return ADDRESS_KIND_TITLES[kind as MachineAddressKind];
}

/** An age in hours, short: "18h", "3d". */
export function hoursAge(hours: number | null | undefined): string | null {
  if (hours == null || !Number.isFinite(hours) || hours < 0) return null;
  if (hours < 48) return `${Math.max(1, Math.round(hours))}h`;
  return `${Math.round(hours / 24)}d`;
}

/** A machine role as the list and the machine page show it. */
export interface MachineRoleView {
  /** The chip text. */
  text: string;
  /** The small state word beside the chip, or null. */
  note: string | null;
  /** The role the accent colour keys on. Null when the role is withheld or
   *  unknown, so a guess never wears the colour of an answer. */
  accent: string | null;
  state: MachineRoleState;
  /** One or two sentences for the hover. */
  title: string;
  /** A withheld role in two parts, for a narrow cell: the guess, whole, and
   *  the state words that qualify it ("low confidence", "stale 8d"). The list
   *  cut "low confidence: security appliance" to "security applianc". Null
   *  when the state names no guess. */
  guess?: string | null;
  qualifier?: string | null;
}

/**
 * The role, with its state, in one place for both screens.
 *
 * declared: the operator's role. inferred: the sweep's role. low_confidence:
 * "low confidence: <guess>". stale: "stale <age>: <guess>". unknown: "unknown".
 */
export function machineRoleView(role: MachineRole | null | undefined): MachineRoleView {
  const state: MachineRoleState = role?.state ?? 'unknown';
  const label = (slug: string | null | undefined): string | null => {
    const v = (slug ?? '').trim();
    return v ? roleLabel(v) : null;
  };
  const answer = (role?.label ?? '').trim() || label(role?.value);
  const guess = label(role?.guess) ?? answer;
  if ((state === 'declared' || state === 'inferred') && answer) {
    return {
      text: answer,
      note: state,
      accent: role?.value ?? answer,
      state,
      title:
        state === 'declared'
          ? 'An operator declared this role.'
          : 'The sweep inferred this role from the evidence.',
    };
  }
  if (state === 'low_confidence') {
    return {
      text: guess ? `low confidence: ${guess}` : 'low confidence',
      note: null,
      accent: null,
      state,
      guess: guess ?? null,
      qualifier: 'low confidence',
      title: guess
        ? `The sweep guessed ${guess}. The evidence is too thin to assert it. Declare the role to settle it.`
        : 'The sweep has a faint signal. The evidence is too thin to name a role.',
    };
  }
  if (state === 'stale') {
    const age = hoursAge(role?.stale_hours);
    const head = age ? `stale ${age}` : 'stale';
    return {
      text: guess ? `${head}: ${guess}` : head,
      note: null,
      accent: null,
      state,
      guess: guess ?? null,
      qualifier: head,
      title: `The sweep inferred ${guess ?? 'a role'}. The evidence is ${age ? `${age} old` : 'old'}. Run a sweep to confirm it.`,
    };
  }
  return {
    text: 'unknown',
    note: null,
    accent: null,
    state: 'unknown',
    title: 'The sweep has no role for this machine.',
  };
}
