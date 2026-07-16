// ---------------------------------------------------------------------------
// Domain types — the shape of the FastAPI JSON API the next increment will wire.
// Screens consume these via src/lib/api.ts; never import mock data directly.
// ---------------------------------------------------------------------------

export type Verdict =
  | 'true_positive'
  | 'false_positive'
  | 'needs_more_info'
  | 'inconclusive'
  | 'untriaged';

export type Severity = 'critical' | 'high' | 'medium' | 'low';

export type DetectionKind = 'suricata' | 'sigma' | 'notice';

/** Human triage state on an alert assignment (E2.3). "unassigned" (no owner) is
 * modelled as the ABSENCE of state (null), so a set state is always one of these. */
export type TriageState = 'owned' | 'in_review' | 'done';

/** A FAILED retry stacked on top of a rule's STANDING verdict (E2.1): the newest
 * run crashed (error/cancelled/interrupted) or fell back, while an older genuine
 * verdict still stands. Surfaces the "stayed at Needs Info" mystery — the row
 * keeps its real verdict, and this note flags that the last re-run died. */
export interface LastAttempt {
  /** error | cancelled | interrupted | fallback */
  status: string;
  /** short relative time the failed retry ran ("5m"). */
  ago: string;
}

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
  /** true when the verdict this event carries came from a pipeline-failure
   * fallback run (E1.2). Optional — the backend only stamps it on the group badge
   * today; kept here so a future per-event marker degrades cleanly. */
  fallback?: boolean;
  /** A failed retry stacked on this event's standing verdict (E2.1). Optional —
   * the backend stamps it on the group badge today; kept here for parity so a
   * future per-event marker degrades cleanly. */
  lastAttempt?: LastAttempt | null;
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
  /** human triage state on the assignment (E2.3): "owned" | "in_review" | "done".
   * null/undefined when the rule is unassigned (no owner) — "unassigned" is the
   * absence of an owner, so state is only meaningful alongside an owner. */
  state?: TriageState | null;
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
  /** true when the rule's standing verdict is a pipeline-failure fallback (E1.2) —
   * the badge renders a "pipeline error — retry" chip and the Dashboard excludes it
   * from the Needs-info KPI. */
  fallback?: boolean;
  /** a FAILED retry stacked on top of the standing verdict (E2.1): the newest run
   * crashed or fell back while an older genuine verdict still stands. Renders a
   * small red "· last retry failed {ago}" hint next to the verdict chip and a
   * retry affordance on the row. None when the newest run IS the standing verdict. */
  lastAttempt?: LastAttempt | null;
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
  /** LEGACY (removed approval gate): always null/false from current backends;
   *  kept for wire-compat with old exports. Never actionable. */
  token?: string;
  pending?: boolean;
  /** already carried out by the system (e.g. auto-ack) — render done, not actionable. */
  applied?: boolean;
  /** why it reads as done ("Already acknowledged", "Executed · analyst"); absent = auto-ack default. */
  appliedNote?: string | null;
  /** why a PENDING ack is waiting for a human while auto-ack is armed
   * (severity/exploit-class guard, or confidence below threshold). */
  pendingNote?: string | null;
}

export interface ResolutionProvenance {
  original_verdict: string;
  resolved_via: 'chat' | 'manual';
  resolved_by: string;
  resolved_at: string;
  source_message_id?: number;
}

/** Pipeline-failure provenance (E1.2). Present ONLY on a run whose verdict is a
 * synth-failure fallback (model truncation, gateway 5xx) — a needs_more_info the
 * pipeline never reasoned to. Renders as a distinct "pipeline error — retry"
 * chip, NOT the amber Needs-info pill. Distinct from ResolutionProvenance
 * (manual/chat override) so the two never conflate. */
export interface FallbackProvenance {
  provenance: 'pipeline_fallback' | string;
  phase?: string | null;
  errorType?: string | null;
  hint?: string | null;
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

export type EntityKind = 'compromised' | 'c2' | 'internal' | 'host';
export type EdgeKind = 'beacon' | 'lateral' | 'flow' | 'enrich';

export interface GraphNode {
  id: string;
  /** 0–100 percentages */
  x: number;
  y: number;
  kind: EntityKind;
  label: string;
  /** short locator line under the label ("US · AS13335 Cloudflare" / "internal"). */
  sub?: string;
  /** true when threat intel (blocklist/MISP) flagged this entity. */
  flagged?: boolean;
  /** intel sources behind the flag (bounded server-side; shown in the tooltip). */
  flagSources?: string[];
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
  /** Pipeline-failure provenance (E1.2) — present ONLY when this run failed before
   * reaching a verdict (model truncation / gateway 5xx). Drives the drawer's
   * "failed before reaching a verdict" panel + Re-run, not the amber NMI block. */
  fallback?: FallbackProvenance | null;
  /** Operator ack of a fallback run (dismiss-error) — renders the Dismiss button as done. */
  errorDismissed?: boolean;
  /** Live acked state of this investigation's alert in Security Onion (false on ES error). */
  alertAcked?: boolean;
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
  /** The alert's own @timestamp (ISO) — when the detection actually fired. */
  time?: string | null;
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
  status: 'complete' | 'running' | 'error' | 'cancelled' | 'interrupted';
  when: string;
  ts?: string;
  chatCount?: number;
  /** the alert this run investigated — retries of the same alert share it. */
  alertId?: string;
  /** the canonical run for its alert (latest complete, else latest); others nest under it. */
  isPrimary?: boolean;
  /** true when this run's needs_more_info is a pipeline-failure fallback (E1.2) —
   * rendered as a "pipeline error — retry" chip, filterable, excluded from the NMI KPI. */
  fallback?: boolean;
  /** operator ack of a fallback run (dismiss-error) — the Dashboard's pipeline-error
   * KPI counts only `fallback && !errorDismissed`; the row itself stays a fallback. */
  errorDismissed?: boolean;
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
  /** Follow-up chat messages on this hunt (0 = no chat log). */
  chatCount?: number;
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
  /** 'threat' | 'visibility_gap' | 'observation' — only threat findings drive
   *  the "Malicious/Suspicious activity found" disposition headline. */
  category?: string;
  hosts: string[];
  citations: string[];
  /** Set by the deterministic post-hunt citation gate when it stripped
   *  non-resolving citations or capped severity (mirrors Investigation). */
  validatorNote?: string | null;
}

export interface HuntAction {
  title: string;
  rationale: string;
}

/** One (category/time, value) datum in a model-authored hunt chart. */
export interface HuntChartPoint {
  x: string;
  y: number;
}

/** A model-authored chart of a numeric series pulled from tool results (e.g. a
 *  beacon-interval histogram, bytes-over-time). Only charts that survived the
 *  post-hunt chart gate (source_citations resolved to gathered evidence) reach
 *  the client — an invented series is dropped and never rendered. */
export interface HuntChart {
  kind: 'bar' | 'line' | 'timeline';
  title: string;
  xLabel?: string;
  yLabel?: string;
  series: HuntChartPoint[];
  sourceCitations?: string[];
}

/** One finding in a hunt-diff bucket — light: title + severity + category. */
export interface HuntDiffEntry {
  title: string;
  severity: string;
  category: string;
}

/** The finding-level diff of a hunt vs the previous COMPLETE run of the SAME
 *  objective (new / persisting / resolved), with the baseline run's timestamp.
 *  Present only when a previous completed run exists. */
export interface HuntDiff {
  new: HuntDiffEntry[];
  persisting: HuntDiffEntry[];
  resolved: HuntDiffEntry[];
  previousHuntId: string;
  previousTs: string;
  previousWhen: string;
}

/** A hunt's full detail: objective, status, narrative, findings, trace timeline. */
export interface HuntDetailData {
  id: string;
  objective: string;
  kind: HuntKind;
  status: HuntStatus;
  narrative: string;
  findings: HuntFinding[];
  /** Model-authored charts that survived the post-hunt chart gate (optional). */
  charts?: HuntChart[];
  affectedHosts: string[];
  mitreTechniques: string[];
  recommendedActions: HuntAction[];
  confidence: number;
  startedBy: string;
  elapsedLabel: string;
  elapsedSec: number;
  ts: string;
  timeline: TimelineStep[];
  /** "vs last run" finding diff — null/absent on the first run of an objective. */
  diff?: HuntDiff | null;
}

export interface HostSignal {
  time: string;
  label: string;
  tone: Severity;
  /** bar width 0–100 */
  w: number;
  sev: string;
}

// ---- Entity pivot page (E3.5) ----------------------------------------------
// A read-model merging an entity's (host or IP) investigations + hunt findings
// into one time-sorted timeline — "what do we know about this box". Mirrors the
// /api/v1/entity/{value} JSON shape (EntityOut). Distinct from the graph's
// EntityKind (node role); this is the URL value's cheap ip-vs-host class.

export type EntityValueKind = 'ip' | 'host' | 'unknown';

/** One merged item in an entity's timeline — an investigation OR a hunt finding. */
export interface EntityTimelineItem {
  ts: string;
  kind: 'investigation' | 'hunt_finding';
  title: string;
  /** investigation-only */
  verdict?: Verdict | null;
  confidence?: number | null;
  /** hunt_finding-only */
  severity?: string | null;
  category?: string | null;
  /** in-app SPA path to the source investigation / hunt. */
  link: string;
}

export interface EntitySummary {
  investigationCount: number;
  huntFindingCount: number;
  latestVerdict?: Verdict | null;
}

/** An entity's full pivot view: value + kind + merged newest-first timeline. */
export interface EntityDetail {
  value: string;
  kind: EntityValueKind;
  timeline: EntityTimelineItem[];
  summary: EntitySummary;
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
  /** Top-level Config-page header this group nests under (server-owned map). */
  parent?: string;
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

// Bulk re-hunt on the Hunts page: each re-hunt is a CLEAN re-run of the
// objective (no prior-narrative seeding), and the batch is throttled — only the
// first few are STARTED, the rest come back skipped/"queued" (routes_hunts.py
// ::bulk_rehunt _REHUNT_START_CAP).
export interface HuntRehuntResult {
  started: { old_id: string; new_id: string; objective: string }[];
  skipped: { id: string; reason: string }[];
}

export interface HuntBulkDeleteResult {
  deleted: string[];
  not_found: string[];
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
  | 'inconclusive'
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
