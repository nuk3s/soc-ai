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
  /** Relative time of the investigation that gave this event its verdict
   * ("8m" → "investigated 8m ago"), for both direct and inherited cases. */
  investigatedAt?: string | null;
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
  /** representative flow from the group's latest event — both hosts (src → dst). */
  src?: string | null;
  dst?: string | null;
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
  /** already carried out by the system (e.g. auto-ack) — render done, not actionable. */
  applied?: boolean;
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
  // 'error' arrives when the backend reaper marks a stuck run as failed;
  // 'interrupted' when a restart cut a run off (benign, re-huntable) — the
  // drawer renders a terminal state for both.
  status: 'complete' | 'investigating' | 'error' | 'cancelled' | 'interrupted';
  elapsedLabel: string;
  /** real elapsed seconds at fetch time — seeds the ticker so it survives nav. */
  elapsedSec?: number;
  actions: RecommendedAction[];
  timeline: TimelineStep[];
  /** Ordered model reasoning traces (the <think> blocks) — the "show your work". */
  reasoning?: string[];
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
  /** destination IP — paired with `host` (source) for the full flow. */
  dst?: string | null;
  status: 'complete' | 'running' | 'awaiting' | 'error' | 'cancelled' | 'interrupted';
  when: string;
  ts?: string;
  chatCount?: number;
  /** the alert this run investigated — retries of the same alert share it. */
  alertId?: string;
  /** the canonical run for its alert (latest complete, else latest); others nest under it. */
  isPrimary?: boolean;
}

// ---- Hunts -----------------------------------------------------------------
// A Hunt is broader than an Investigation: it correlates across hosts/time or a
// free-form objective and lands findings + a narrative (a HuntReport), not a
// single-alert verdict. These mirror the /api/v1/hunts* JSON shapes.

export type HuntStatus = 'running' | 'complete' | 'error' | 'cancelled' | 'interrupted';
export type HuntKind = 'chat' | 'scheduled' | 'triggered';

/** One row in the Hunts list. */
export interface HuntRow {
  id: string;
  objective: string;
  kind: HuntKind;
  status: HuntStatus;
  findingCount: number;
  affectedHosts: number;
  confidence: number | null;
  startedBy: string;
  when: string;
  ts: string;
}

export interface HuntStat {
  label: string;
  value: string;
  sub: string;
  tone: 'accent' | 'sigma' | 'warn' | 'danger';
}

/** One finding a hunt turned up, backed by evidence. */
export interface HuntFinding {
  title: string;
  detail: string;
  severity: string;
  hosts: string[];
  citations: string[];
}

export interface HuntAction {
  title: string;
  rationale: string;
}

/** A hunt's full detail: objective, status, narrative, findings, trace timeline. */
export interface HuntDetailData {
  id: string;
  objective: string;
  kind: HuntKind;
  status: HuntStatus;
  narrative: string;
  findings: HuntFinding[];
  affectedHosts: string[];
  mitreTechniques: string[];
  recommendedActions: HuntAction[];
  confidence: number;
  startedBy: string;
  elapsedLabel: string;
  elapsedSec: number;
  ts: string;
  timeline: TimelineStep[];
}

export interface HostSignal {
  time: string;
  label: string;
  tone: Severity;
  /** bar width 0–100 */
  w: number;
  sev: string;
}

// ---- Config ----------------------------------------------------------------

export type SettingSource = 'db' | 'env';
export type SettingApply = 'hot-apply' | 'restart';
export type SettingType = 'toggle' | 'number' | 'select' | 'text';

export interface Setting {
  key: string;
  /** human label shown as the field title (the raw key is a secondary hint). */
  label: string;
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
  id: string;
  tone: 'danger' | 'warn' | 'accent';
  title: string;
  when: string;
  href?: string | null;
}

// ── Backtest ("prove it on my last N days") ─────────────────────────────────
// Replay soc-ai's triage over a sample of already-dispositioned alerts and
// compare its verdicts to the analyst's REAL Security Onion disposition.

export type BacktestRunStatus = 'running' | 'complete' | 'error';

/** The two ground-truth disposition labels + the two settled soc-ai verdicts,
 * plus the hedge and the "no verdict produced" bucket. */
export type HumanDisposition = 'true_positive' | 'false_positive';
export type SocVerdict =
  | 'true_positive'
  | 'false_positive'
  | 'needs_more_info'
  | 'no_verdict';

/** One replayed alert: what the analyst said vs. what soc-ai said. */
export interface BacktestRow {
  alert_id: string;
  rule_name: string;
  human_disposition: HumanDisposition;
  soc_ai_verdict: SocVerdict | null;
  match: boolean;
}

/** human_disposition → { soc verdict → count }. */
export type BacktestConfusion = Record<HumanDisposition, Record<SocVerdict, number>>;

export interface BacktestMetrics {
  agreement_rate: number;
  fp_reduction: number;
  missed_tp: number;
  n_needs_more_info: number;
  counts: {
    total: number;
    human_tp: number;
    human_fp: number;
    agreements: number;
    fp_cleared: number;
  };
}

export interface BacktestResults {
  metrics: BacktestMetrics;
  confusion: BacktestConfusion;
  missed_tp_rows: BacktestRow[];
  rows: BacktestRow[];
  caveat: string;
}

export interface BacktestParams {
  window_days: number;
  sample_size: number;
  requested_sample_size?: number;
  min_severity: string | null;
}

/** The current/last backtest: live progress while running, stored results when
 * complete. Mirrors the backend BacktestStatusOut. */
export interface Backtest {
  active: boolean;
  backtest_id: string | null;
  total: number;
  replayed: number;
  failed: number;
  finished_at: string | null;
  current: string | null;
  note: string | null;
  params: BacktestParams | null;
  results: BacktestResults | null;
  status: BacktestRunStatus | null;
  sampled: number | null;
}

export interface StartBacktestOpts {
  windowDays: number;
  sampleSize: number;
  minSeverity?: string;
}
