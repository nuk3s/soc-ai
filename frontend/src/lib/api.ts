// ---------------------------------------------------------------------------
// Data-access boundary. ALL screen data flows through these async functions.
//
// Today they resolve mock data. In the next increment each body is swapped for a
// fetch() against the FastAPI JSON API — the function signatures and return
// types stay identical, so no screen has to change. Screens MUST consume these
// asynchronously (loading / empty / error states) and never import ./mock.
// ---------------------------------------------------------------------------

import type {
  AdminUser,
  AlertEvent,
  AlertGroup,
  ChatMessage,
  Config,
  ConnTestResult,
  DangerSetting,
  HuntDetail,
  HuntRow,
  HuntStat,
  Investigation,
  InvestigationRow,
  Me,
  Notification,
  RehuntResult,
  RepresentativeOut,
  Workspace,
} from './types';

/** JSON-body POST helper. */
function post<T>(path: string, body?: unknown): Promise<T> {
  return request<T>(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
}

/** DELETE helper. */
function del<T>(path: string): Promise<T> {
  return request<T>(path, { method: 'DELETE' });
}

// ---------------------------------------------------------------------------
// Real API plumbing. Endpoints that have been wired to the FastAPI JSON API
// (/api/v1) use request(); the rest still resolve mock data above until their
// increment lands. Same-origin in prod (served under /app), so the session
// cookie flows; a VITE_API_TOKEN bearer is used in cross-origin dev.
// ---------------------------------------------------------------------------
const API_BASE = '/api/v1';

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const token = import.meta.env.VITE_API_TOKEN as string | undefined;
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (init?.headers) Object.assign(headers, init.headers as Record<string, string>);
  if (token) headers.Authorization = `Bearer ${token}`;

  let res: Response;
  try {
    res = await fetch(API_BASE + path, { credentials: 'include', ...init, headers });
  } catch {
    throw new Error('Network error — is the soc-ai API reachable?');
  }

  if (res.status === 401) {
    // Not authenticated / session expired — hand off to the React login page.
    window.location.href = '/app/login';
    throw new Error('Unauthorized');
  }
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      const hint = body?.detail?.hint ?? (typeof body?.detail === 'string' ? body.detail : null);
      if (hint) detail = hint;
    } catch {
      /* non-JSON error body — keep the status line */
    }
    throw new Error(detail);
  }
  return (await res.json()) as T;
}

export interface AlertQuery {
  range?: string; // a preset ('24h') or 'custom'
  from?: string; // datetime-local, when range === 'custom'
  to?: string;
  severity?: string; // '' = all, else critical|high|medium|low
  hideAcked?: boolean; // when true, exclude acknowledged/escalated groups
}

function alertQueryParams(query: AlertQuery, base: Record<string, string> = {}): string {
  const p = new URLSearchParams(base);
  if (query.range === 'custom' && query.from && query.to) {
    p.set('from', query.from);
    p.set('to', query.to);
  } else if (query.range) {
    p.set('range', query.range);
  }
  if (query.severity) p.set('severity', query.severity);
  if (query.hideAcked) p.set('hide_acked', 'true');
  return p.toString();
}

export function getAlerts(query: AlertQuery = {}): Promise<AlertGroup[]> {
  const qs = alertQueryParams(query);
  return request<AlertGroup[]>('/alerts' + (qs ? `?${qs}` : ''));
}

/** Lazy-load the events inside one detection group (fetched on row expand). */
export function getAlertGroupEvents(
  group: Pick<AlertGroup, 'name' | 'kind'>,
  query: AlertQuery = {},
): Promise<AlertEvent[]> {
  const qs = alertQueryParams(query, { rule_name: group.name, kind: group.kind });
  return request<AlertEvent[]>(`/alerts/events?${qs}`);
}

/**
 * Pick the most-representative event for a collapsed group.
 * Selects the event whose (src_ip, dst_ip, dst_port) tuple is the most common
 * across the cluster; returns the ES _id to hunt and a reason string.
 */
export function getRepresentative(
  group: Pick<AlertGroup, 'name' | 'kind'>,
  query: AlertQuery = {},
): Promise<RepresentativeOut> {
  const qs = alertQueryParams(query, { rule_name: group.name, kind: group.kind });
  return request<RepresentativeOut>(`/alerts/representative?${qs}`);
}

export function getInvestigations(): Promise<InvestigationRow[]> {
  return request<InvestigationRow[]>('/investigations');
}

/**
 * Resolve an investigation by its INV-id (permalink) or by the alert es-id it
 * was opened from (drawer) — the backend resolves the latter to that alert's
 * latest run.
 */
export function getInvestigation(idOrGroupId: string): Promise<Investigation> {
  return request<Investigation>(`/investigations/${encodeURIComponent(idOrGroupId)}`);
}

export function getHunts(): Promise<HuntRow[]> {
  return request<HuntRow[]>('/hunts');
}

export function getHuntStats(): Promise<HuntStat[]> {
  return request<HuntStat[]>('/hunts/stats');
}

// ---------------------------------------------------------------------------
// Mock HuntDetail rows — one entry per MOCK_HUNTS id from Hunts.tsx.
// The hunting-agent backend doesn't exist yet; this lets HuntDetail render
// its preview content behind an in-development banner instead of erroring.
// ---------------------------------------------------------------------------
const MOCK_HUNT_DETAILS: Record<string, HuntDetail> = {
  'h-zerologon': {
    hunt: {
      id: 'h-zerologon',
      name: 'Zerologon DCE/RPC pattern',
      type: 'scheduled',
      query:
        'event.dataset:zeek.dce_rpc AND zeek.dce_rpc.operation:(NetrServerAuthenticate3 OR NetrServerReqChallenge) | groupby source.ip | sortby count',
      schedule: 'every 4h',
      last: '2h ago',
      findings: 2,
      maxSev: 'critical',
      status: 'active',
      host: '192.0.2.1',
    },
    nodes: [
      { id: 'n1', x: 20, y: 50, kind: 'host', label: '192.0.2.1' },
      { id: 'n2', x: 70, y: 50, kind: 'dc', label: 'DC-01' },
    ],
    edges: [{ from: 'n1', to: 'n2', kind: 'lateral', label: 'NetrServerAuthenticate3' }],
    riskScore: 88,
    riskLabel: 'Critical Risk',
    riskDesc: 'Zerologon exploit attempt pattern detected against domain controller.',
    hostSignals: [
      { time: '02:14', label: 'NetrServerAuthenticate3 burst', tone: 'critical', w: 95, sev: 'CRIT' },
      { time: '02:12', label: 'NetrServerReqChallenge × 31', tone: 'high', w: 78, sev: 'HIGH' },
    ],
    patterns: [
      { tone: '#f04438', label: 'Auth brute', detail: '31 ops / 2 min' },
    ],
    sequence: [
      { tone: '#f04438', name: 'ReqChallenge', time: '02:12' },
      { tone: '#f04438', name: 'Authenticate3 burst', time: '02:14' },
    ],
    findings: [
      { tone: 'critical', title: 'Zerologon exploit pattern — NetrServerAuthenticate3 × 31 in 2 min', host: '192.0.2.1', when: '2h ago' },
      { tone: 'high', title: 'DC-01 auth error spike co-incident with DCE/RPC burst', host: '192.0.2.1', when: '2h ago' },
    ],
  },

  // ---------------------------------------------------------------------------
  // DCSync / DRSCrackNames — T1003.006: OS Credential Dumping via Directory Replication
  // A non-DC host issuing drsuapi RPC calls is a near-certain credential harvest.
  // ---------------------------------------------------------------------------
  'h-dcsync': {
    hunt: {
      id: 'h-dcsync',
      name: 'DCSync / DRSCrackNames activity',
      type: 'scheduled',
      query:
        'event.dataset:zeek.dce_rpc AND zeek.dce_rpc.endpoint:drsuapi AND zeek.dce_rpc.operation:(DRSCrackNames OR DRSGetNCChanges) | groupby source.ip',
      schedule: 'every 4h',
      last: '2h ago',
      findings: 1,
      maxSev: 'high',
      status: 'active',
      host: '192.0.2.10',
    },
    nodes: [
      { id: 'n1', x: 15, y: 50, kind: 'compromised', label: '192.0.2.10' },
      { id: 'n2', x: 60, y: 50, kind: 'dc', label: 'DC-01' },
      { id: 'n3', x: 85, y: 28, kind: 'dc', label: 'DC-02' },
    ],
    edges: [
      { from: 'n1', to: 'n2', kind: 'lateral', label: 'DRSGetNCChanges' },
      { from: 'n1', to: 'n3', kind: 'lateral', label: 'DRSCrackNames' },
    ],
    riskScore: 82,
    riskLabel: 'High Risk',
    riskDesc: 'Non-DC workstation issuing drsuapi replication calls — consistent with DCSync credential dumping (T1003.006).',
    hostSignals: [
      { time: '14:07', label: 'DRSGetNCChanges from workstation', tone: 'high', w: 88, sev: 'HIGH' },
      { time: '14:06', label: 'DRSCrackNames — username resolution', tone: 'high', w: 74, sev: 'HIGH' },
      { time: '14:05', label: 'drsuapi bind from non-DC source', tone: 'medium', w: 55, sev: 'MED' },
    ],
    patterns: [
      { tone: '#f5a623', label: 'Replication abuse', detail: 'DRSGetNCChanges × 4' },
      { tone: '#f04438', label: 'Cred harvest', detail: 'NTDS dump likely' },
    ],
    sequence: [
      { tone: '#f5a623', name: 'drsuapi bind', time: '14:05' },
      { tone: '#f5a623', name: 'DRSCrackNames', time: '14:06' },
      { tone: '#f04438', name: 'DRSGetNCChanges', time: '14:07' },
    ],
    findings: [
      { tone: 'high', title: 'DCSync pattern — DRSGetNCChanges from non-DC host 192.0.2.10 to DC-01 and DC-02', host: '192.0.2.10', when: '2h ago' },
    ],
  },

  // ---------------------------------------------------------------------------
  // AD Enumeration — SAMR/LSAR  (T1087.002: Account Discovery – Domain Account)
  // High volume of SamrEnumerateUsersInDomain / LsarEnumerateAccounts signals
  // automated recon tooling (BloodHound, SharpHound, Net-based enum).
  // ---------------------------------------------------------------------------
  'h-ad-enum': {
    hunt: {
      id: 'h-ad-enum',
      name: 'AD enumeration — SAMR/LSAR',
      type: 'scheduled',
      query:
        'event.dataset:zeek.dce_rpc AND zeek.dce_rpc.endpoint:(samr OR lsarpc) AND zeek.dce_rpc.operation:(SamrEnumerateUsersInDomain OR LsarEnumerateAccounts) | groupby source.ip',
      schedule: 'every 6h',
      last: '4h ago',
      findings: 7,
      maxSev: 'high',
      status: 'active',
      host: '192.0.2.88',
    },
    nodes: [
      { id: 'n1', x: 12, y: 50, kind: 'compromised', label: '192.0.2.88' },
      { id: 'n2', x: 48, y: 30, kind: 'dc', label: 'DC-01' },
      { id: 'n3', x: 48, y: 70, kind: 'host', label: 'FS-01' },
      { id: 'n4', x: 80, y: 50, kind: 'host', label: 'WKS-14' },
    ],
    edges: [
      { from: 'n1', to: 'n2', kind: 'lateral', label: 'SamrEnumerateUsersInDomain' },
      { from: 'n1', to: 'n3', kind: 'flow', label: 'LsarEnumerateAccounts' },
      { from: 'n1', to: 'n4', kind: 'flow', label: 'samr bind' },
    ],
    riskScore: 71,
    riskLabel: 'High Risk',
    riskDesc: 'Automated SAMR/LSAR enumeration from a single source to 3 hosts — characteristic of BloodHound / SharpHound collector run.',
    hostSignals: [
      { time: '09:32', label: 'SamrEnumerateUsersInDomain × 148', tone: 'high', w: 92, sev: 'HIGH' },
      { time: '09:31', label: 'LsarEnumerateAccounts × 67', tone: 'high', w: 76, sev: 'HIGH' },
      { time: '09:30', label: 'samr / lsarpc bind burst', tone: 'medium', w: 58, sev: 'MED' },
      { time: '09:29', label: 'Reverse DNS lookups × 200+', tone: 'medium', w: 44, sev: 'MED' },
    ],
    patterns: [
      { tone: '#f5a623', label: 'Domain recon', detail: '148 SAMR ops' },
      { tone: '#f5a623', label: 'ACL crawl', detail: 'LSAR × 67' },
      { tone: '#4b8bf5', label: 'Multi-host sweep', detail: '3 targets · 3 min' },
    ],
    sequence: [
      { tone: '#4b8bf5', name: 'RPC bind burst', time: '09:29' },
      { tone: '#f5a623', name: 'LSAR enum', time: '09:31' },
      { tone: '#f5a623', name: 'SAMR user enum', time: '09:32' },
    ],
    findings: [
      { tone: 'high', title: 'BloodHound-like SAMR sweep — 148 SamrEnumerateUsersInDomain calls from 192.0.2.88 in 3 min', host: '192.0.2.88', when: '4h ago' },
      { tone: 'high', title: 'LsarEnumerateAccounts × 67 — privilege and group reconnaissance against DC-01', host: '192.0.2.88', when: '4h ago' },
      { tone: 'medium', title: 'SAMR bind to file-server FS-01 from non-admin workstation', host: '192.0.2.88', when: '4h ago' },
      { tone: 'medium', title: 'SAMR bind to WKS-14 — lateral recon target', host: '192.0.2.88', when: '4h ago' },
      { tone: 'medium', title: 'Bulk reverse-DNS lookups co-timed with SAMR sweep (T1018)', host: '192.0.2.88', when: '4h ago' },
      { tone: 'medium', title: 'samr / lsarpc RPC bind volume anomaly — 3× daily baseline', host: '192.0.2.88', when: '4h ago' },
      { tone: 'low', title: 'RPC endpoint mapper query spike from single host prior to enumeration', host: '192.0.2.88', when: '4h ago' },
    ],
  },

  // ---------------------------------------------------------------------------
  // Beaconing over zeek.conn — T1071.001: Application Layer Protocol / C2 beacon
  // Coefficient-of-variation analysis on zeek.conn flows catches periodic C2
  // sleep+jitter patterns invisible to signature detections.
  // ---------------------------------------------------------------------------
  'h-beacon': {
    hunt: {
      id: 'h-beacon',
      name: 'Beaconing over zeek.conn (CV)',
      type: 'scheduled',
      query:
        'event.dataset:zeek.conn | groupby source.ip,destination.ip | sortby count desc | head 500',
      schedule: 'every 1h',
      last: 'running',
      findings: 5,
      maxSev: 'medium',
      status: 'running',
      host: '192.0.2.15',
    },
    nodes: [
      { id: 'n1', x: 18, y: 50, kind: 'compromised', label: '192.0.2.15' },
      { id: 'n2', x: 75, y: 50, kind: 'c2', label: '198.51.100.42' },
    ],
    edges: [{ from: 'n1', to: 'n2', kind: 'beacon', label: 'HTTP/S · 60 s jitter' }],
    riskScore: 65,
    riskLabel: 'Medium Risk',
    riskDesc: 'Low-CV periodic outbound HTTPS to external IP — consistent with a C2 beacon (Cobalt Strike / Sliver sleep jitter pattern).',
    hostSignals: [
      { time: '11:00', label: 'HTTPS beacon to 198.51.100.42 (JA3 match)', tone: 'medium', w: 82, sev: 'MED' },
      { time: '10:59', label: 'Periodic conn interval CV < 0.05', tone: 'medium', w: 68, sev: 'MED' },
      { time: '10:45', label: 'Staged HTTP GET — small payload pull', tone: 'medium', w: 52, sev: 'MED' },
      { time: '10:30', label: 'DNS query for stage domain (NX→A transition)', tone: 'low', w: 35, sev: 'LOW' },
    ],
    patterns: [
      { tone: '#f5a623', label: 'Periodic beacon', detail: 'CV 0.032 · 58 s avg' },
      { tone: '#a472f0', label: 'JA3 fingerprint', detail: '72a589da586844d7f' },
      { tone: '#4b8bf5', label: 'Small payload', detail: '280 B avg resp' },
    ],
    sequence: [
      { tone: '#4b8bf5', name: 'DNS stage lookup', time: '10:30' },
      { tone: '#4b8bf5', name: 'HTTP staged pull', time: '10:45' },
      { tone: '#f5a623', name: 'Periodic HTTPS beacon', time: '11:00' },
    ],
    findings: [
      { tone: 'medium', title: 'Low-CV beacon to 198.51.100.42 — 58 s interval, CV 0.032, JA3 fingerprint match (T1071.001)', host: '192.0.2.15', when: 'running' },
      { tone: 'medium', title: 'JA3 fingerprint 72a589da586844d7f matches known Cobalt Strike default TLS profile', host: '192.0.2.15', when: 'running' },
      { tone: 'medium', title: 'HTTP staged payload pull before beacon start — two-stage loader pattern', host: '192.0.2.15', when: 'running' },
      { tone: 'medium', title: 'External IP 198.51.100.42 not in allow-list — no business justification', host: '192.0.2.15', when: 'running' },
      { tone: 'low', title: 'DNS NX→A resolution transition for stage domain 30 min before beacon', host: '192.0.2.15', when: 'running' },
    ],
  },

  // ---------------------------------------------------------------------------
  // DNS tunneling / DGA entropy — T1071.004: Application Layer Protocol / DNS
  // High-entropy subdomains, NXDOMAIN bursts, and anomalous query volumes are
  // hallmarks of DNS data exfiltration (iodine, dnscat2) or DGA malware.
  // ---------------------------------------------------------------------------
  'h-dns-dga': {
    hunt: {
      id: 'h-dns-dga',
      name: 'DNS tunneling / DGA entropy',
      type: 'scheduled',
      query:
        'event.dataset:zeek.dns AND dns.query.type_name:A | groupby dns.question.registered_domain | sortby count desc',
      schedule: 'every 2h',
      last: '1h ago',
      findings: 4,
      maxSev: 'medium',
      status: 'active',
      host: '192.0.2.22',
    },
    nodes: [
      { id: 'n1', x: 15, y: 50, kind: 'compromised', label: '192.0.2.22' },
      { id: 'n2', x: 55, y: 50, kind: 'host', label: 'DNS-Resolver' },
      { id: 'n3', x: 85, y: 50, kind: 'c2', label: 'tunnel.exfil-ns.net' },
    ],
    edges: [
      { from: 'n1', to: 'n2', kind: 'flow', label: 'high-entropy A queries' },
      { from: 'n2', to: 'n3', kind: 'beacon', label: 'recursed upstream' },
    ],
    riskScore: 60,
    riskLabel: 'Medium Risk',
    riskDesc: 'High-entropy subdomain labels and anomalous NXDOMAIN rate from single host — consistent with DNS tunnel or DGA beacon (T1071.004).',
    hostSignals: [
      { time: '07:18', label: 'High-entropy labels — avg 22 char per subdomain', tone: 'medium', w: 80, sev: 'MED' },
      { time: '07:16', label: 'NXDOMAIN rate 43 % — 3× resolver baseline', tone: 'medium', w: 68, sev: 'MED' },
      { time: '07:15', label: 'DNS query volume 1 200 req / 5 min spike', tone: 'medium', w: 55, sev: 'MED' },
      { time: '07:10', label: 'Long label detected: 63-char subdomain', tone: 'low', w: 38, sev: 'LOW' },
    ],
    patterns: [
      { tone: '#f5a623', label: 'High entropy', detail: 'H > 3.8 bits / char' },
      { tone: '#f5a623', label: 'NXDOMAIN burst', detail: '43 % rate' },
      { tone: '#4b8bf5', label: 'Query volume', detail: '1 200 req / 5 min' },
    ],
    sequence: [
      { tone: '#4b8bf5', name: 'Volume spike', time: '07:15' },
      { tone: '#f5a623', name: 'NXDOMAIN burst', time: '07:16' },
      { tone: '#f5a623', name: 'High-entropy labels', time: '07:18' },
    ],
    findings: [
      { tone: 'medium', title: 'DNS tunnel pattern — 1 200 queries in 5 min with avg 22-char entropy-rich subdomains (T1071.004)', host: '192.0.2.22', when: '1h ago' },
      { tone: 'medium', title: 'NXDOMAIN rate 43 % for domain tunnel.exfil-ns.net — consistent with DGA polling', host: '192.0.2.22', when: '1h ago' },
      { tone: 'medium', title: '63-character subdomain label detected — exceeds RFC 1035 typical limit, suggests encoding', host: '192.0.2.22', when: '1h ago' },
      { tone: 'low', title: 'DNS resolver 192.0.2.53 recursed all anomalous queries upstream — not cached', host: '192.0.2.22', when: '1h ago' },
    ],
  },

  // ---------------------------------------------------------------------------
  // ATTACK::Discovery notices sweep — T1046/T1018/T1082 (Zeek ATTACK notice layer)
  // Ad-hoc sweep of Zeek ATTACK::* notices to surface reconnaissance bursts.
  // High finding count reflects a broad sweep over a 3-day window.
  // ---------------------------------------------------------------------------
  'h-adhoc-notice': {
    hunt: {
      id: 'h-adhoc-notice',
      name: 'ATTACK::Discovery notices sweep',
      type: 'ad-hoc',
      query:
        'event.dataset:zeek.notice AND zeek.notice.note:ATTACK::* | groupby zeek.notice.note,source.ip | sortby count',
      schedule: 'on demand',
      last: '3d ago',
      findings: 11,
      maxSev: 'high',
      status: 'complete',
      host: '192.0.2.88',
    },
    nodes: [
      { id: 'n1', x: 12, y: 50, kind: 'compromised', label: '192.0.2.88' },
      { id: 'n2', x: 40, y: 28, kind: 'dc', label: 'DC-01' },
      { id: 'n3', x: 40, y: 72, kind: 'host', label: 'SRV-03' },
      { id: 'n4', x: 68, y: 50, kind: 'host', label: 'WKS-07' },
      { id: 'n5', x: 88, y: 36, kind: 'host', label: 'WKS-11' },
    ],
    edges: [
      { from: 'n1', to: 'n2', kind: 'lateral', label: 'ATTACK::Discovery' },
      { from: 'n1', to: 'n3', kind: 'flow', label: 'ATTACK::Lateral' },
      { from: 'n1', to: 'n4', kind: 'flow', label: 'PortScan' },
      { from: 'n4', to: 'n5', kind: 'lateral', label: 'ATTACK::Execution' },
    ],
    riskScore: 76,
    riskLabel: 'High Risk',
    riskDesc: '11 Zeek ATTACK::* notice types from a single source across 4 hosts over 72 h — multi-stage reconnaissance and lateral movement campaign indicators.',
    hostSignals: [
      { time: '3d ago', label: 'ATTACK::Discovery × 342 notices', tone: 'high', w: 90, sev: 'HIGH' },
      { time: '3d ago', label: 'ATTACK::LateralMovement × 18', tone: 'high', w: 74, sev: 'HIGH' },
      { time: '3d ago', label: 'ATTACK::Execution × 7', tone: 'high', w: 62, sev: 'HIGH' },
      { time: '3d ago', label: 'PortScan against WKS-07 / SRV-03', tone: 'medium', w: 48, sev: 'MED' },
    ],
    patterns: [
      { tone: '#f04438', label: 'Multi-tactic', detail: '11 ATTACK notice types' },
      { tone: '#f5a623', label: 'Lateral spread', detail: '4 hosts · 72 h' },
      { tone: '#4b8bf5', label: 'Recon volume', detail: '342 Discovery notices' },
    ],
    sequence: [
      { tone: '#4b8bf5', name: 'Discovery sweep', time: '3d ago' },
      { tone: '#f5a623', name: 'Port scan', time: '3d ago' },
      { tone: '#f04438', name: 'Lateral + Execution', time: '3d ago' },
    ],
    findings: [
      { tone: 'high', title: 'ATTACK::Discovery — 342 notices from 192.0.2.88, 4 distinct destination hosts (T1046 / T1018)', host: '192.0.2.88', when: '3d ago' },
      { tone: 'high', title: 'ATTACK::LateralMovement × 18 — source host reached DC-01 and SRV-03', host: '192.0.2.88', when: '3d ago' },
      { tone: 'high', title: 'ATTACK::Execution × 7 on WKS-11 — preceded by lateral movement from WKS-07', host: '192.0.2.88', when: '3d ago' },
      { tone: 'high', title: 'PortScan notice to WKS-07 (T1046) — 1 022 ports in 45 s', host: '192.0.2.88', when: '3d ago' },
      { tone: 'medium', title: 'ATTACK::Collection notices × 5 after Execution phase — possible staging', host: '192.0.2.88', when: '3d ago' },
      { tone: 'medium', title: 'ATTACK::Persistence × 3 against DC-01 — scheduled task or service creation', host: '192.0.2.88', when: '3d ago' },
      { tone: 'medium', title: 'ATTACK::CredentialAccess × 2 on SRV-03 — co-timed with SAMR enum', host: '192.0.2.88', when: '3d ago' },
      { tone: 'medium', title: 'ATTACK::DefenseEvasion notice on WKS-07 — LOLBin invocation pattern', host: '192.0.2.88', when: '3d ago' },
      { tone: 'medium', title: 'ATTACK::CommandAndControl × 4 — periodic small flows to 203.0.113.77', host: '192.0.2.88', when: '3d ago' },
      { tone: 'low', title: 'ATTACK::Exfiltration notice × 1 — 22 MB upload spike at end of campaign window', host: '192.0.2.88', when: '3d ago' },
      { tone: 'low', title: 'ATTACK::Impact × 1 — suspect shadow copy query on DC-01', host: '192.0.2.88', when: '3d ago' },
    ],
  },

  // ---------------------------------------------------------------------------
  // Sigma rule candidate — Zerologon
  // Ad-hoc hunt that produced a focused Sigma candidate rule. Complete status
  // with 3 critical findings used to draft the detection logic.
  // ---------------------------------------------------------------------------
  'h-adhoc-sigma-draft': {
    hunt: {
      id: 'h-adhoc-sigma-draft',
      name: 'Sigma rule candidate — Zerologon',
      type: 'ad-hoc',
      query: 'event.dataset:zeek.dce_rpc AND zeek.dce_rpc.operation:NetrServerAuthenticate3',
      schedule: 'on demand',
      last: '5d ago',
      findings: 3,
      maxSev: 'critical',
      status: 'complete',
      host: '192.0.2.1',
    },
    nodes: [
      { id: 'n1', x: 20, y: 50, kind: 'host', label: '192.0.2.1' },
      { id: 'n2', x: 65, y: 50, kind: 'dc', label: 'DC-01' },
    ],
    edges: [{ from: 'n1', to: 'n2', kind: 'lateral', label: 'NetrServerAuthenticate3' }],
    riskScore: 91,
    riskLabel: 'Critical Risk',
    riskDesc: 'Three independent events matching the focused Sigma candidate — all originating from the same source, confirming the rule logic fires accurately on real data.',
    hostSignals: [
      { time: '5d ago', label: 'NetrServerAuthenticate3 (event 1 of 3)', tone: 'critical', w: 97, sev: 'CRIT' },
      { time: '5d ago', label: 'NetrServerAuthenticate3 (event 2 of 3)', tone: 'critical', w: 94, sev: 'CRIT' },
      { time: '5d ago', label: 'NetrServerAuthenticate3 (event 3 of 3)', tone: 'critical', w: 89, sev: 'CRIT' },
    ],
    patterns: [
      { tone: '#f04438', label: 'Rule candidate fires', detail: '3 / 3 TP confirmed' },
      { tone: '#a472f0', label: 'Sigma draft', detail: 'condition: all of them' },
    ],
    sequence: [
      { tone: '#f04438', name: 'Event 1 — Auth3', time: '5d ago' },
      { tone: '#f04438', name: 'Event 2 — Auth3', time: '5d ago' },
      { tone: '#f04438', name: 'Event 3 — Auth3', time: '5d ago' },
    ],
    findings: [
      { tone: 'critical', title: 'Sigma candidate confirmed TP #1 — NetrServerAuthenticate3 at null-byte machine-password (CVE-2020-1472)', host: '192.0.2.1', when: '5d ago' },
      { tone: 'critical', title: 'Sigma candidate confirmed TP #2 — repeat pattern 4 min later, same source, different session ID', host: '192.0.2.1', when: '5d ago' },
      { tone: 'critical', title: 'Sigma candidate confirmed TP #3 — DC auth error (STATUS_ACCESS_DENIED) follows each attempt', host: '192.0.2.1', when: '5d ago' },
    ],
  },
};

// Fall back to a generic mock for any id not explicitly listed above.
function _genericHuntDetail(id: string): HuntDetail {
  return {
    hunt: {
      id,
      name: id,
      type: 'scheduled',
      query: 'event.dataset:zeek.conn | groupby source.ip | sortby count desc',
      schedule: 'on demand',
      last: '—',
      findings: 0,
      maxSev: 'low',
      status: 'complete',
      host: '—',
    },
    nodes: [],
    edges: [],
    riskScore: 0,
    riskLabel: 'No data',
    riskDesc: 'Mock preview — hunting agent not yet available.',
    hostSignals: [],
    patterns: [],
    sequence: [],
    findings: [],
  };
}

export function getHuntDetail(id: string): Promise<HuntDetail> {
  // No saved-hunt backend yet — hunting agent ships in a future increment.
  // Resolve illustrative mock data so HuntDetail renders its preview behind
  // an in-development banner instead of showing an error page.
  const detail = MOCK_HUNT_DETAILS[id] ?? _genericHuntDetail(id);
  return Promise.resolve(detail);
}

export function getConfig(): Promise<Config> {
  return request<Config>('/config');
}

export function getWorkspaces(): Promise<Workspace[]> {
  return request<Workspace[]>('/workspaces');
}

export function getNotifications(): Promise<Notification[]> {
  return request<Notification[]>('/notifications');
}

export interface HealthComponent {
  ok: boolean;
  detail: string;
}
export interface Health {
  es: HealthComponent;
  llm: HealthComponent;
  pcap?: HealthComponent | null;
}

/** Live upstream status (ES / LLM / PCAP) for the header indicator. */
export function getHealth(): Promise<Health> {
  return request<Health>('/health');
}

// ---- mutations ------------------------------------------------------------

/** Start a background investigation for an alert; resolves to the new INV id. */
export function startHunt(alertId: string): Promise<string> {
  return post<{ investigation_id: string }>('/hunt', { alert_id: alertId }).then(
    (r) => r.investigation_id,
  );
}

/** Re-launch fresh investigations for a set of existing investigation ids. */
export function rehuntInvestigations(invIds: string[]): Promise<RehuntResult> {
  return post<RehuntResult>('/investigations/rehunt', { inv_ids: invIds });
}

export interface ChatThread {
  messages: ChatMessage[];
  pending: boolean;
}

export function getChatThread(invId: string): Promise<ChatThread> {
  return request<ChatThread>(`/investigations/${encodeURIComponent(invId)}/chat`);
}

export function postChat(invId: string, message: string): Promise<ChatThread> {
  return post<ChatThread>(`/investigations/${encodeURIComponent(invId)}/chat`, { message });
}

/** Apply a validated chat verdict proposal. */
export function resolveInvestigation(invId: string, messageId: number, token: string): Promise<unknown> {
  return post(`/investigations/${encodeURIComponent(invId)}/resolve`, { message_id: messageId, token });
}

/** Manually override a completed investigation's verdict. */
export function overrideVerdict(
  invId: string,
  verdict: string,
  rationale?: string,
  confidence?: number,
): Promise<{ ok: boolean; verdict: string; confidence: number }> {
  return post(`/investigations/${encodeURIComponent(invId)}/override`, {
    verdict,
    rationale: rationale ?? null,
    confidence: confidence ?? null,
  });
}

export function approveAction(token: string, approved: boolean, reason?: string): Promise<unknown> {
  return post('/approve', { token, approved, reason: reason ?? null });
}

export interface ExecuteActionResult {
  status: 'executed' | 'error';
  title: string;
  detail: string;
  error: string | null;
}

/** Execute one advisory (report-recommended) write action against Security Onion. */
export function executeAction(invId: string, index: number): Promise<ExecuteActionResult> {
  return post<ExecuteActionResult>(
    `/investigations/${encodeURIComponent(invId)}/actions/${index}/execute`,
  );
}

export function setSetting(
  key: string,
  value: string,
): Promise<{ ok: boolean; restart_required: boolean }> {
  return post('/config/setting', { key, value });
}

/** Mint an API token — the raw value is returned once. */
export function mintToken(name = 'console'): Promise<string> {
  return post<{ token: string }>('/config/tokens', { name }).then((r) => r.token);
}

export function revokeToken(id: number): Promise<unknown> {
  return post(`/config/tokens/${id}/revoke`);
}

export function listUsers(): Promise<{ users: AdminUser[] }> {
  return request<{ users: AdminUser[] }>('/config/users');
}

export function createUser(username: string, password: string, role: string): Promise<{ ok: boolean }> {
  return post<{ ok: boolean }>('/config/users', { username, password, role });
}

export function toggleUserDisabled(id: number): Promise<{ ok: boolean; disabled: boolean }> {
  return post<{ ok: boolean; disabled: boolean }>(`/config/users/${id}/toggle-disabled`);
}

export function resetUserPassword(id: number): Promise<{ ok: boolean; password: string }> {
  return post<{ ok: boolean; password: string }>(`/config/users/${id}/reset-password`);
}

export function setUserRole(id: number, role: string): Promise<{ ok: boolean }> {
  return post<{ ok: boolean }>(`/config/users/${id}/set-role`, { role });
}

/** Return the currently-logged-in user's username, role, and status. */
export function getMe(): Promise<Me> {
  return request<Me>('/me');
}

/** Update the current user's status string (trim + cap enforced server-side). */
export function setMyStatus(status: string): Promise<{ ok: boolean; status: string }> {
  return post<{ ok: boolean; status: string }>('/me/status', { status });
}

// ── Danger-zone API ───────────────────────────────────────────────────────────

export function listDangerSettings(): Promise<DangerSetting[]> {
  return request<DangerSetting[]>('/config/danger');
}

export function saveDangerSetting(
  key: string,
  value: string,
  confirm: string,
): Promise<{ ok: boolean; restart_required: boolean }> {
  return post<{ ok: boolean; restart_required: boolean }>('/config/danger/setting', {
    key,
    value,
    confirm,
  });
}

export function testConnection(target: 'es' | 'llm'): Promise<ConnTestResult> {
  return post<ConnTestResult>(`/config/danger/test/${target}`);
}

export interface AutoTriageStatus {
  active: boolean;
  total: number;
  hunted: number;
  skipped: number;
  failed: number;
  finished_at: string | null;
  severities: string[];
  note: string | null;
  current: string | null;
  tool_calls: number;
}

const _SEV_LADDER = ['critical', 'high', 'medium', 'low'] as const;

/** Return every severity at or above `floor` (e.g. "high" → ["critical","high"]). */
export function severitiesAtOrAbove(floor: string): string[] {
  const i = _SEV_LADDER.indexOf(floor as typeof _SEV_LADDER[number]);
  return i < 0 ? ['critical', 'high'] : Array.from(_SEV_LADDER.slice(0, i + 1));
}

/** Launch a background auto-triage batch.
 *  - `alertIds` — triages exactly that selection (already-verdicted skipped).
 *  - `minSeverity` — sweeps all detections at or above this severity floor;
 *    omit to let the backend use its configured default (auto_triage_min_severity).
 *  - Both omitted — backend uses its configured default. */
export function startAutoTriage(opts?: { alertIds?: string[]; minSeverity?: string }): Promise<AutoTriageStatus> {
  const body: Record<string, unknown> = {};
  if (opts?.alertIds?.length) {
    body.alert_ids = opts.alertIds;
  } else if (opts?.minSeverity) {
    body.severities = severitiesAtOrAbove(opts.minSeverity);
  }
  return post<AutoTriageStatus>('/auto-triage', body);
}

export function getAutoTriageStatus(): Promise<AutoTriageStatus> {
  return request<AutoTriageStatus>('/auto-triage');
}

export interface AckGroupResult {
  acked: number;
  failed: number;
  total: number;
  capped: boolean;
}

export interface AssignResult {
  rule_name: string;
  owner: string | null;
}

/**
 * Assign (or unassign) the logged-in caller as owner of a detection rule.
 * Returns the persisted owner (username / token name) or null after unassign.
 */
export function assignAlert(ruleName: string, unassign = false): Promise<AssignResult> {
  return post<AssignResult>('/alerts/assign', { rule_name: ruleName, unassign });
}

/** Acknowledge all events for a detection group via the SO ack_alert write tool. */
export function ackGroup(group: AlertGroup, query: AlertQuery = {}): Promise<AckGroupResult> {
  const body: Record<string, string | undefined> = { rule_name: group.name, kind: group.kind };
  if (query.range === 'custom' && query.from && query.to) {
    body.from_ = query.from;
    body.to = query.to;
  } else if (query.range) {
    body.range = query.range;
  }
  if (query.severity) body.severity = query.severity;
  return post<AckGroupResult>('/alerts/ack-group', body);
}

/** Acknowledge a specific set of events by ES id (per-event selection). */
export function ackEvents(esIds: string[]): Promise<AckGroupResult> {
  return post<AckGroupResult>('/alerts/ack-events', { es_ids: esIds });
}

// ── Internal-identifier managed list ────────────────────────────────────────────

/** Discovery scan-now status (reused for the "last scan" caption). */
export interface DiscoveryScanStatus {
  running: boolean;
  last_scan: string | null;
  last_summary: Record<string, unknown> | null;
  note: string | null;
}

/** Provenance for a detected identifier (compactly formatted for display). */
export interface IdentifierEvidence {
  host_count?: number;
  event_count?: number;
  first_seen?: string;
  last_seen?: string;
  sample?: string[];
  [k: string]: unknown;
}

/**
 * One managed-list entry. Mutable DB rows carry an `id` and `mutable: true`;
 * read-only always-on env/reserved entries have `id: null`, `mutable: false`.
 */
export interface IdentifierRow {
  id: number | null;
  value: string;
  source: 'detected' | 'manual' | 'reserved' | 'env';
  state: 'active' | 'muted';
  evidence: IdentifierEvidence | null;
  mutable: boolean;
}

export type IdentifierKind = 'suffix' | 'host' | 'cidr';

export interface IdentifierGroup {
  kind: IdentifierKind;
  rows: IdentifierRow[];
}

export interface InternalIdentifiers {
  groups: IdentifierGroup[];
  last_scan: DiscoveryScanStatus;
}

/** The internal-identifier managed list, grouped by kind, plus last-scan meta. */
export function getInternalIdentifiers(): Promise<InternalIdentifiers> {
  return request<InternalIdentifiers>('/internal-identifiers');
}

/** Add a manual identifier. Throws (400) on a bad kind / invalid value. */
export function addInternalIdentifier(kind: IdentifierKind, value: string): Promise<IdentifierRow> {
  return post<IdentifierRow>('/internal-identifiers', { kind, value });
}

/** Activate (on = used to redact/classify) or deactivate an identifier. */
export function setIdentifierActive(id: number, active: boolean): Promise<IdentifierRow> {
  return post<IdentifierRow>(`/internal-identifiers/${id}/${active ? 'activate' : 'deactivate'}`);
}

/** Remove a manual identifier. Throws (409) for a detected row — deactivate instead. */
export function removeIdentifier(id: number): Promise<{ ok: boolean }> {
  return del<{ ok: boolean }>(`/internal-identifiers/${id}`);
}

/** Launch a background discovery scan; returns the (running) status. */
export function startDiscoveryScan(): Promise<DiscoveryScanStatus> {
  return post<DiscoveryScanStatus>('/discovery/scan');
}

/** Poll the discovery scan status. */
export function getDiscoveryScan(): Promise<DiscoveryScanStatus> {
  return request<DiscoveryScanStatus>('/discovery/scan');
}

// ── Auth ──────────────────────────────────────────────────────────────────────

export interface LoginResult {
  ok: boolean;
  username: string;
  role: string;
}

/**
 * Authenticate against the JSON API.  On success the server sets the session
 * cookie; subsequent same-origin requests carry it automatically.
 * Throws on network error or bad credentials (401).
 */
export async function login(username: string, password: string): Promise<LoginResult> {
  // Use fetch directly — not request() — so a 401 here does NOT redirect to
  // /app/login (we're already on the login page and want to surface the error).
  let res: Response;
  try {
    res = await fetch(API_BASE + '/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ username, password }),
    });
  } catch {
    throw new Error('Network error — is the soc-ai API reachable?');
  }
  if (res.status === 401) {
    throw new Error('Invalid username or password');
  }
  if (!res.ok) {
    throw new Error(`Login failed: ${res.status} ${res.statusText}`);
  }
  return (await res.json()) as LoginResult;
}

/** Destroy the current session and clear the cookie. */
export async function logout(): Promise<void> {
  try {
    await fetch(API_BASE + '/logout', {
      method: 'POST',
      headers: { Accept: 'application/json' },
      credentials: 'include',
    });
  } catch {
    // Best-effort — if the request fails we still navigate to login.
  }
}
