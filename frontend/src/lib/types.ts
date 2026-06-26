// ---------------------------------------------------------------------------
// Domain types — the shape of the FastAPI JSON API the next increment will wire.
// Screens consume these via src/lib/api.ts; never import mock data directly.
// ---------------------------------------------------------------------------

export type Verdict =
  | 'true_positive'
  | 'false_positive'
  | 'needs_more_info'
  | 'untriaged';

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export type DetectionKind = 'suricata' | 'sigma' | 'notice';

export interface AlertEvent {
  id?: string;
  src: string;
  dst: string;
  host: string;
  proto?: string;
  sev?: string;
  port?: number | null;
  ts?: string;
  ago?: string;
  /** True when this exact event's es_id was directly investigated. */
  investigated?: boolean;
  /** Investigation id whose verdict applies to this event (direct or inherited). */
  invId?: string | null;
  /** Human-readable reason when the verdict is inherited rather than direct. */
  inheritedReason?: string | null;
}

/** A grouped-by-detection row in the Alerts console. */
export interface AlertGroup {
  id: string;
  name: string;
  kind: DetectionKind;
  sev: Severity;
  count: number;
  verdict: Verdict;
  conf: number | null;
  latest: string;
  /** raw ISO timestamp for latest event — used for chronological sorting. */
  latestTs?: string;
  /** verdict inherited from a sibling/parent group (dashed pill, "· inherited"). */
  inherited: boolean;
  /** default owner initials, if any. */
  owner?: string;
  events: AlertEvent[];
  /** the investigation behind the verdict badge — the drawer opens it directly. */
  invId?: string;
  /** when the verdict is inherited, a short reason (same detection, other alert). */
  inheritedReason?: string;
  /** true while the rule's latest investigation is still running — show "Triaging…" pill. */
  triaging?: boolean;
  /** number of acknowledged events in this group (from ES aggs). */
  ackedCount?: number;
  /** number of escalated events in this group (from ES aggs). */
  escalatedCount?: number;
}

// ---- Representative-event picker -------------------------------------------

/** Returned by GET /api/v1/alerts/representative — the most-common-flow event. */
export interface RepresentativeOut {
  alert_id: string;
  src_ip: string | null;
  dst_ip: string | null;
  dst_port: number | null;
  matched: number;
  total: number;
  reason: string;
}

// ---- Investigation ---------------------------------------------------------

export type TimelineGroup =
  | 'Prefetch & pivots'
  | 'Indicator enrichment'
  | 'Tool calls'
  | 'Decision'
  | 'Validators'
  | 'Oracle';

export interface TimelineStep {
  id: string;
  group: TimelineGroup;
  title: string;
  time: string;
  detail: string;
}

export type ActionTag = 'ack' | 'escalate' | 'comment';

export interface RecommendedAction {
  id: string;
  title: string;
  tag: ActionTag;
  rationale: string;
  /** live approval-gate token — present only while the action is actionable. */
  token?: string;
  pending?: boolean;
}

export interface ResolutionProvenance {
  original_verdict: string;
  resolved_via: 'chat' | 'manual';
  resolved_by: string;
  resolved_at: string;
  source_message_id?: number;
}

export interface VerdictProposal {
  verdict: Verdict;
  confidence: number;
  rationale: string;
  citations: string[];
  recommended_actions: { tool_name: string; tool_args: Record<string, unknown>; rationale: string }[];
}

export interface ChatMessage {
  role: 'user' | 'assistant';
  text: string;
  tools?: string;
  messageId?: number;
  kind?: 'verdict_proposal';
  validation?: 'pass' | 'fail';
  objection?: string | null;
  token?: string;
  applied?: boolean;
  proposal?: VerdictProposal;
}

export type EntityKind = 'compromised' | 'c2' | 'dc' | 'host';
export type EdgeKind = 'beacon' | 'lateral' | 'flow' | 'enrich';

export interface GraphNode {
  id: string;
  /** 0–100 percentages */
  x: number;
  y: number;
  kind: EntityKind;
  label: string;
}

export interface GraphEdge {
  from: string;
  to: string;
  kind: EdgeKind;
  label?: string;
}

export interface Investigation {
  id: string;
  /** alert-group id this investigation was opened from (drawer routing). */
  groupId: string;
  name: string;
  kind: DetectionKind;
  host: string;
  ip: string;
  verdict: Verdict;
  conf: number;
  rationale: string;
  /** structured summary so citations can be rendered as accent superscripts. */
  summary: SummarySegment[];
  // 'error' arrives when the backend reaper marks a stuck/interrupted run as
  // failed — the drawer renders a terminal error state for it.
  status: 'complete' | 'investigating' | 'error';
  elapsedLabel: string;
  /** real elapsed seconds at fetch time — seeds the ticker so it survives nav. */
  elapsedSec?: number;
  actions: RecommendedAction[];
  timeline: TimelineStep[];
  nodes: GraphNode[];
  edges: GraphEdge[];
  seedChat: ChatMessage[];
  // Richer analyst context — surfaced in the wide permalink layout (the compact
  // drawer omits these). Optional so investigations without them degrade cleanly.
  sev?: Severity;
  alert?: AlertMeta;
  hostContext?: HostSignal[];
  meta?: InvMeta;
  /** Structured Oracle (2nd-opinion) adjudication — present only when Oracle was consulted. */
  oracle?: OracleAdjudication | null;
  /** One-line blast-radius summary shown in the collapsed entity-graph bar. */
  graphNote?: string;
  /** Unresolved gaps from a needs_more_info verdict — seeds the resolve-in-chat flow. */
  openQuestions?: string[];
  /** Manual or chat provenance — present when the AI verdict was overridden. */
  resolution?: ResolutionProvenance;
  /** Post-validator override note — present when a validator auto-corrected the verdict. */
  validatorNote?: string | null;
}

/** The triggering detection's raw facts — the "what fired" reference panel. */
export interface AlertMeta {
  id?: string;
  rule: string;
  sid?: string;
  classtype?: string;
  category?: string;
  src: string;
  dst: string;
  proto: string;
  action: string; // 'allowed' | 'blocked'
  firstSeen: string;
  lastSeen: string;
  count: number;
}

/** How the verdict was produced — the investigation provenance panel. */
export interface InvMeta {
  model: string;
  oracle?: string;
  ranBy: string;
  ranAt: string;
  toolCalls: number;
  pivots: number;
}

/** Structured Oracle (2nd-opinion model) adjudication result. */
export interface OracleAdjudication {
  escalated: boolean;
  reason?: string;
  localVerdict?: string;
  localConfidence?: number;
  oracleVerdict?: string;
  oracleConfidence?: number;
  model?: string;
  redacted?: boolean;
  redactionNote?: string;
  changed?: boolean;
}

export type SummarySegment =
  | { t: 'text'; v: string }
  | { t: 'mono'; v: string; tone?: 'amber' | 'green' }
  | { t: 'cite'; n: number };

export interface InvestigationRow {
  id: string;
  name: string;
  kind: DetectionKind;
  verdict: Verdict;
  conf: number | null;
  host: string;
  status: 'complete' | 'running' | 'awaiting' | 'error';
  when: string;
  ts?: string;
  chatCount?: number;
}

// ---- Hunts -----------------------------------------------------------------

export type HuntType = 'scheduled' | 'ad-hoc';
export type HuntStatus = 'active' | 'running' | 'complete';

export interface HuntRow {
  id: string;
  name: string;
  type: HuntType;
  query: string;
  schedule: string;
  last: string;
  findings: number;
  /** max severity among findings — drives the findings dot color. */
  maxSev: Severity;
  status: HuntStatus;
  host: string;
}

export interface HuntStat {
  label: string;
  value: string;
  sub: string;
  tone: 'accent' | 'sigma' | 'warn' | 'danger';
}

export interface HostSignal {
  time: string;
  label: string;
  tone: Severity;
  /** bar width 0–100 */
  w: number;
  sev: string;
}

export interface Finding {
  tone: Severity;
  title: string;
  host: string;
  when: string;
}

export interface TimelinePattern {
  tone: string;
  label: string;
  detail: string;
}

export interface TimelinePhase {
  tone: string;
  name: string;
  time: string;
}

export interface HuntDetail {
  hunt: HuntRow;
  nodes: GraphNode[];
  edges: GraphEdge[];
  riskScore: number;
  riskLabel: string;
  riskDesc: string;
  hostSignals: HostSignal[];
  patterns: TimelinePattern[];
  sequence: TimelinePhase[];
  findings: Finding[];
}

// ---- Config ----------------------------------------------------------------

export type SettingSource = 'db' | 'env';
export type SettingApply = 'hot-apply' | 'restart';
export type SettingType = 'toggle' | 'number' | 'select' | 'text';

export interface Setting {
  key: string;
  help: string;
  source: SettingSource;
  apply: SettingApply;
  type: SettingType;
  value: boolean | number | string;
  bounds?: string;
  options?: string[];
}

export interface SettingGroup {
  title: string;
  items: Setting[];
}

export interface ApiToken {
  id: number;
  name: string;
  prefix: string;
  created: string;
  used: string;
}

export interface AdminUser {
  id: number;
  username: string;
  role: string;         // "admin" | "analyst"
  disabled: boolean;
  status: string;       // free-text, "" when unset
  lastLoginAt?: string; // ISO timestamp or undefined
}

export interface Me {
  username: string;
  role: string;
  status: string;
}

export interface Config {
  groups: SettingGroup[];
  tokens: ApiToken[];
  users: AdminUser[];
  dangerHost: string;
}

// ── Danger-zone types ─────────────────────────────────────────────────────────

export type DangerSettingType = 'secret' | 'text' | 'bool' | 'csv';
export type DangerSettingSource = 'env' | 'db' | 'unset';

export interface DangerSetting {
  key: string;
  label: string;
  type: DangerSettingType;
  isSet: boolean;
  source: DangerSettingSource;
  hot: boolean;
}

export interface ConnTestResult {
  ok: boolean;
  detail: string;
}

// ---- Bulk re-hunt ----------------------------------------------------------

export interface RehuntResult {
  started: { invId: string; newInvId: string; alertEsId: string }[];
  skipped: { invId: string; reason: string }[];
}

// ---- Shell -----------------------------------------------------------------

export interface Workspace {
  name: string;
  env: 'prod' | 'staging';
}

export interface Notification {
  tone: 'danger' | 'warn' | 'accent';
  title: string;
  when: string;
}
