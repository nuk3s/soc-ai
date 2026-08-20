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

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

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
  /** Flow endpoints. NOT nullable on the wire: the backend substitutes the
   * literal "—" when the event has none, so emptiness has to be tested for by
   * value (see `pivotTarget` in Alerts.tsx) — a truthiness check passes it. */
  src: string;
  dst: string;
  host: string;
  /** Address of the machine the detection fired ON (its endpoint agent), for
   * host-shaped detections — Sigma process/file rules carry no source.ip or
   * destination.ip at all, so this is the analyst's only pivotable address.
   * Deliberately NOT a flow endpoint: the backend keeps it out of src/dst
   * because those are the sweep's cluster key and would assert a connection
   * nobody observed. Absent (undefined/null) on ordinary flow alerts. */
  hostIp?: string | null;
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

/** A disposition the investigation chat's agent drafted for the analyst to apply. */
export interface VerdictProposal {
  verdict: Verdict;
  confidence: number;
  rationale: string;
  citations: string[];
  recommended_actions: { tool_name: string; tool_args: Record<string, unknown>; rationale: string }[];
}

/** A sweep the Dashboard chat's agent wrote for the analyst to confirm — never
 *  auto-started. Written by `propose_hunt`, the general chat's mirror of
 *  `propose_verdict`. */
export interface HuntProposal {
  /** The hunt brief the agent wrote, sharpened by what it just looked at. */
  objective: string;
  /** One line on what the sweep would settle that the turn could not. */
  why: string;
}

/** Fields every chat row carries, whatever it proposes. `messageId`/`validation`/
 *  `objection`/`token`/`applied` are serialized only on proposal rows
 *  (`_chat_msg_out` gates them on `PROPOSAL_KINDS`), but they stay here rather
 *  than on each variant so a reader can ask about them without narrowing. */
interface ChatMessageBase {
  role: 'user' | 'assistant';
  text: string;
  tools?: string;
  /** Row id the apply/resolve call echoes back. */
  messageId?: number;
  validation?: 'pass' | 'fail';
  objection?: string | null;
  token?: string;
  /** Whether the proposal was already acted on. `false` (not absent) on hunt rows. */
  applied?: boolean;
}

/** An ordinary answer: prose, maybe a tools footer, nothing to confirm. */
export interface ChatAnswerMessage extends ChatMessageBase {
  kind?: undefined;
  proposal?: undefined;
}

export interface ChatVerdictProposalMessage extends ChatMessageBase {
  kind: 'verdict_proposal';
  proposal: VerdictProposal;
}

export interface ChatHuntProposalMessage extends ChatMessageBase {
  kind: 'hunt_proposal';
  proposal: HuntProposal;
}

/**
 * One row of any chat thread — the backend serializes every surface through a
 * single `ChatMessageOut`, so one type serves them all.
 *
 * A discriminated union on `kind`, deliberately: `proposal`'s SHAPE depends on
 * which agent wrote it (`PROPOSAL_KINDS` in api/webui/_timeline.py is the
 * authority), and typing it as one shape is how the second kind arrived — a
 * hunt proposal that could not be expressed without a cast. Adding a third kind
 * means adding a variant here, and every site that reads `proposal` without
 * narrowing on `kind` stops compiling, instead of silently reading `undefined`
 * off a shape it never expected.
 */
export type ChatMessage =
  | ChatAnswerMessage
  | ChatVerdictProposalMessage
  | ChatHuntProposalMessage;

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

/** One SQL page of GET /api/v1/investigations — the /dossiers list shape.
 *
 * `total` / `running` / `truePositives` are counted SERVER-SIDE over the same
 * filter set as `rows`. Never re-derive them from `rows`: the page is capped,
 * and a page-local tally describing itself as the filter set's is the
 * phantom-untriaged defect this shape exists to prevent. `totalAll` / `active`
 * describe the whole store (empty-store vs. no-match copy; poll gating). */
export interface InvestigationList {
  rows: InvestigationRow[];
  total: number;
  running: number;
  truePositives: number;
  totalAll: number;
  active: boolean;
  /** The clamped values the server actually used — page by these. */
  limit: number;
  offset: number;
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
  /** Day-1 tier (server-curated): true = shown by default; false = folded
   * behind the section's "Advanced" reveal. Never hardcode which keys are
   * day1 on the frontend — this flag is the only source of truth. */
  day1: boolean;
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

// ---- About + update check --------------------------------------------------

/** `/about` as the API serves it: build metadata plus the feature flags a screen
 *  has to know BEFORE it renders. */
export interface AboutInfo {
  version: string;
  repo_url: string;
  license: string;
  update_check_enabled: boolean;
  /**
   * The Dashboard assistant's kill switch. It rides on this response — a payload
   * every session already fetches — so the SPA can hide the box instead of
   * mounting one whose first GET is a guaranteed 403.
   *
   * OPTIONAL because an older backend omits it, and "unknown" has to mean ON:
   * the setting defaults on, so treating a missing field as off would silently
   * delete the feature for anyone running a mixed build.
   */
  general_chat_enabled?: boolean;
}

export interface UpdateCheckResult {
  enabled: boolean;
  ok: boolean;
  current_version: string;
  latest_version: string | null;
  update_available: boolean;
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
  /** Over the DECIDED rows only — a replay that produced no verdict is a row
   *  soc-ai never judged, not a row it got wrong. Read with `completion_rate`. */
  agreement_rate: number;
  /** Decided rows / sampled rows: how much of the backtest actually ran. */
  completion_rate?: number;
  fp_reduction: number;
  missed_tp: number;
  n_needs_more_info: number;
  n_no_verdict?: number;
  counts: {
    total: number;
    decided?: number;
    no_verdict?: number;
    human_tp: number;
    human_fp: number;
    human_fp_decided?: number;
    agreements: number;
    fp_cleared: number;
  };
}

/** How much of the sample was replayed, and whether the run was cut short.
 *  A backtest that lost the grid mid-run used to finalize `complete` with the
 *  blind replays priced as model disagreement — a persisted, wrong conclusion
 *  about model quality caused by an infrastructure failure. */
export interface BacktestCompletion {
  total: number;
  decided: number;
  no_verdict: number;
  completion_rate: number;
  degraded: boolean;
  reason: string | null;
}

export interface BacktestResults {
  metrics: BacktestMetrics;
  completion?: BacktestCompletion;
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

// ── Host dossier ("what IS this host?") ─────────────────────────────────────
// Per field the backend keeps TWO physically separate lanes — what the network
// sweep inferred, and what an operator declared — and stores no "current value"
// anywhere. A resolver decides the effective answer at read time, operator lane
// first, so everything below is already-resolved output. Screens render it; they
// never compose an effective value of their own, or the UI and the investigation
// prompt would start describing different hosts.

/** The 12 dossier fields (DOSSIER_FIELDS in soc_ai/dossier/types.py). Spelled as
 *  a union so a mistyped field name is a compile error rather than a 400. Every
 *  response carries all twelve, in the backend's render order — screens map the
 *  response array, they don't hold their own list to sort by. */
export type DossierFieldName =
  | 'hostname'
  | 'mac'
  | 'os_family'
  | 'os_detail'
  | 'role'
  | 'services_offered'
  | 'management_plane'
  | 'domain_membership'
  | 'is_static_addressed'
  | 'activity_profile'
  | 'criticality'
  | 'policy_notes';

/** The three fields a scalar cannot carry: their `value` is null and the answer
 *  rides in `value_json` — including when an operator overrides them. */
export type DossierJsonFieldName = 'services_offered' | 'activity_profile' | 'management_plane';

/** The provenance ladder, weakest first. Not a scale of certainty but of
 *  directness: what the host did, leaked, announced, reported, then answered. */
export type DossierProvenance = 'behaviour' | 'telemetry' | 'banner' | 'hostlog' | 'osquery';

/** Where a resolved value came from. `operator` is NOT a rung on the ladder — it
 *  is the other lane, and it wins outright. */
export type DossierSource = 'operator' | DossierProvenance;

export type DossierStrength = 'strong' | 'weak' | 'none';

/** Why a field did NOT resolve. `no_signal` and `stale` are different answers:
 *  nothing was ever found vs. nobody has re-checked what was. */
export type DossierUnresolvedReason = 'stale' | 'low_confidence' | 'no_signal';

/** How this build disagrees with a standing override, ordered by how deeply each
 *  undermines it: a different machine now answers on the address (`rebound`), the
 *  evidence the field rested on is gone (`retracted`), or the evidence simply
 *  points elsewhere (`mismatch`). */
export type DossierConflictKind = 'mismatch' | 'retracted' | 'rebound';

/** Column the host list is ordered by. `stale` sorts by how long since the
 *  builder last had anything to say about the host. `importance` is what the
 *  screen LANDS on: declared criticality first, then named, then any host a
 *  human has touched. `attention` inverts that emphasis — broken builds first,
 *  then open conflicts, then operator-declared, then named — and stays one
 *  click away in the sort control, because on an estate where almost nothing
 *  has been built yet it fills the whole first screen with dashes. */
export type DossierSortKey =
  | 'importance'
  | 'attention'
  | 'last_seen'
  | 'first_seen'
  | 'ip'
  | 'stale'
  | 'event_count';

/** The `?health=` prefilter: hosts with no clean build on record (never built,
 *  or the last build errored) — the same set `DossierSummary.never_built`
 *  counts, so the tile and the filtered view cannot disagree. */
export type DossierHealthFilter = 'broken';

/** The `?source=` prefilter: hosts carrying an operator declaration, or hosts
 *  running purely on inference. */
export type DossierLane = 'operator' | 'inferred';

/** An OPEN disagreement, with the state of its rate limiter. Present only while
 *  the lanes actually disagree — the backend NULLs it the moment they agree
 *  again, so a non-null conflict is always live. `prompt_count` survives that
 *  reset (it is history, and the notification cycle id). */
export interface DossierConflict {
  kind: DossierConflictKind | null;
  first_seen_at: string | null;
  observations: number;
  last_prompted_at: string | null;
  prompt_count: number;
  snoozed_until: string | null;
}

/** One resolved field, list-weight: the answer without the paper trail. The
 *  host list can be 200 hosts x 12 fields, so the evidence blob and both
 *  lanes' bookkeeping are detail-page weight. */
export interface DossierFieldBrief {
  field: DossierFieldName;
  value: string | null;
  value_json: unknown;
  /** Null when nothing resolved — read `reason` for why. */
  source: DossierSource | null;
  confidence: number;
  strength: DossierStrength;
  reason: DossierUnresolvedReason | null;
  overridden: boolean;
  conflict_kind: DossierConflictKind | null;
}

/** One resolved field with BOTH lanes and the evidence behind them. The
 *  `inferred_*` half is populated even when an operator override wins: an
 *  override suppresses effect, never observation, and the reconsider card argues
 *  from exactly this pair. */
export interface DossierField extends DossierFieldBrief {
  evidence: Record<string, unknown>;
  observed_at: string | null;
  first_seen: string | null;
  /** Last build that EVALUATED this field, even if it concluded nothing. Null
   *  means never evaluated — "no signal" and "not looked at yet" differ. */
  last_run_at: string | null;
  retracted_at: string | null;
  operator_actor: string | null;
  operator_note: string | null;
  operator_set_at: string | null;
  inferred_value: string | null;
  inferred_value_json: unknown;
  inferred_confidence: number | null;
  inferred_source: DossierProvenance | null;
  conflict: DossierConflict | null;
}

/** One host in the host list. */
export interface DossierRow {
  ip: string;
  /** False for an address the sweep has never seen. That is a real answer served
   *  200 with twelve no_signal fields — "no dossier for this host" — not an error. */
  found: boolean;
  fields: DossierFieldBrief[];
  first_seen: string | null;
  last_seen: string | null;
  last_built_at: string | null;
  last_observed_at: string | null;
  event_count: number;
  /** Set when a DIFFERENT machine appears to hold this address now: an override
   *  on this row may describe a host that has moved on. */
  identity_rebound_at: string | null;
  build_error: string | null;
  override_count: number;
  conflict_count: number;
  /** An agent ON this machine is currently reporting about itself — any field
   *  whose inference lane holds a LIVE value at the hostlog rung, per the
   *  resolver's gates. Explicit on the wire because a client cannot derive it:
   *  an override masks the winning `source` on the field it takes, and the
   *  staleness window is a server knob. Same definition the summary's
   *  `reporting` counts, so the strip and the rows cannot disagree. */
  reporting: boolean;
}

/** One host's full dossier. Narrows `fields` the way the backend's DossierOut
 *  narrows DossierRowOut's — same rows, with the paper trail attached. */
export interface Dossier extends DossierRow {
  fields: DossierField[];
}

export interface DossierList {
  rows: DossierRow[];
  /** The whole match set, not the page — the pager must not have to guess it
   *  from a short page. */
  total: number;
  limit: number;
  offset: number;
}

/** One disagreement that has earned the operator's attention. Carries both
 *  lanes in BOTH shapes: the three JSON-shaped fields are overridden through
 *  `*_value_json` with the scalar left null, and a card reading only the scalars
 *  would render blank on exactly the conflicts that are hardest to read. */
export interface DossierConflictRow {
  ip: string;
  field: DossierFieldName;
  kind: DossierConflictKind | null;
  first_seen_at: string | null;
  observations: number;
  last_prompted_at: string | null;
  prompt_count: number;
  snoozed_until: string | null;
  operator_value: string | null;
  operator_value_json: unknown;
  inferred_value: string | null;
  inferred_value_json: unknown;
  identity_rebound_at: string | null;
  /** Predates the Hosts screen and points at /entity/{ip}; link to /hosts/:ip. */
  href: string;
}

export interface DossierConflicts {
  /** Open disagreements past the observation threshold — the nudge count, in the
   *  detection-tuning `pending` shape the dashboard already renders. */
  pending: number;
  rows: DossierConflictRow[];
}

/** Network-wide dossier counts — the WHOLE table, never the page on screen.
 *
 * Mirrors DossierSummaryOut in soc_ai/api/webui/routes_dossier.py. It exists as
 * its own request precisely so the host list's KPI strip cannot be computed
 * from `DossierList.rows`: that is one SQL page of up to 5,000 hosts, and a
 * headline count taken off it would describe a fiftieth of the network. */
export interface DossierSummary {
  hosts: number;
  /** No clean build on record: never swept at all, or the last sweep errored. */
  never_built: number;
  /** Hosts whose `hostname` the RESOLVER will assert — an operator's value, or
   *  an inferred one past the confidence floor and inside the staleness window.
   *  A stored name the resolver withholds is not counted, so this agrees with
   *  the Hostname column in the table beneath it. */
  named: number;
  /** Hosts whose inference lane holds a value at the `hostlog` rung: an agent on
   *  the machine reporting about itself. Counts the OBSERVATION, so an operator
   *  override on the field does not hide it. */
  reporting: number;
  /** Open disagreements past the observation gate — the same count
   *  `DossierConflicts.pending` carries, from the same store predicate. */
  conflicts: number;
  /** Hosts per EFFECTIVE role — the operator's declaration first, else an
   *  inferred role the resolver would assert. Hosts with no resolved role join
   *  no bucket, so the values need not sum to `hosts`: the difference is the
   *  unresolved remainder the distribution bar draws in gray. */
  roles: Record<string, number>;
  /** The newest build stamp in the table; null when nothing has ever been swept. */
  last_built_at: string | null;
  /** Whether sweeps run on a schedule. Off by default, in which case these
   *  counts are only as fresh as the last manual Rebuild. */
  schedule_enabled: boolean;
  /** The classifier's closed role vocabulary (soc_ai.dossier.infer.ROLE_VOCABULARY).
   *  The host filter and the declare datalist read it from here so they offer
   *  every role the classifier can emit — not only the ones a host on the
   *  current page carries. Optional so an older server, or a mock, degrades to
   *  the frontend's ROLE_VOCABULARY fallback rather than an empty list. */
  role_vocabulary?: string[];
}

/** Network-sweep run state. `note` reads 'dossier disabled' when the master
 *  switch is off — nothing was started, and that is not an error. */
export interface DossierRefreshStatus {
  running: boolean;
  last_run: string | null;
  last_summary: Record<string, unknown> | null;
  note: string | null;
}

// ---- Host activity (live half of the host page) -----------------------------
// What a host is DOING, read off the grid on the request that renders it. The
// dossier above is swept and cached and keeps answering while Security Onion is
// down; this cannot, and the page fetches the two independently so only the half
// that failed degrades. Mirrors HostActivityOut in
// soc_ai/api/webui/routes_dossier.py.

/** The two windows the endpoint accepts. Closed, not the alerts console's free
 *  time picker: the volume histogram's bucket width is derived from it (hourly
 *  for 24h, daily for 7d), so anything else is a 422 rather than a silently
 *  re-bucketed chart. */
export type HostActivityRange = '24h' | '7d';

/** One address this host exchanged traffic with over the window. */
export interface HostPeer {
  ip: string;
  /** The peer's own dossier hostname, when the network knows it. */
  hostname: string | null;
  direction: 'in' | 'out' | 'both';
  ports: number[];
  events: number;
  /** An alert in the window names this peer — the one thing that makes a line on
   *  the peer graph worth following. */
  alerted: boolean;
}

/** One histogram bucket. The server sets NO extended_bounds, so the series does
 *  not necessarily span the whole window: a host quiet at the edges simply has
 *  fewer points, and nothing may assume a fixed bucket count. */
export interface VolumePoint {
  ts: string;
  events: number;
}

/** One account seen authenticating on this host in the window. */
export interface UserSeen {
  name: string;
  events: number;
  last_seen: string;
}

/** The most recent investigation naming this host. `verdict` is null while a run
 *  is still in flight — a live investigation is worth linking to before it has
 *  concluded anything. */
export interface LatestInvestigation {
  id: string;
  verdict: string | null;
  ts: string;
}

export interface HostActivity {
  peers: HostPeer[];
  volume: VolumePoint[];
  /** NULL, not `[]`, for an address the grid holds no host-log authentication
   *  documents for — and it is WINDOW-scoped, so a host that ships auth logs but
   *  was quiet reads null too. Screens must not turn it into a claim about the
   *  machine's logging that the query never proved. */
  users: UserSeen[] | null;
  alerts_7d: number;
  latest_investigation: LatestInvestigation | null;
  /** The server ranked and CUT the peer list — rows fell off the end. Decided
   *  by the backend from the pre-cut length; screens must not re-infer it from
   *  list lengths against a copied cap constant. */
  peers_truncated: boolean;
  /** Same contract for the account list. Always false when `users` is null:
   *  an absent list is not a cut one. */
  users_truncated: boolean;
}

// ── Saved list views ────────────────────────────────────────────────────────

/** The four list screens that can hold a saved view (backend:
 *  soc_ai/store/saved_views.SAVED_VIEW_SCREENS). */
export type SavedViewScreen = 'alerts' | 'investigations' | 'hunts' | 'hosts';

/** A screen's filter state, as stored. Opaque to the backend on purpose: the
 *  screen that writes a view is the screen that reads it back. */
export type SavedViewQuery = Record<string, unknown>;

/** One analyst's named filter set for one list screen. Server-held and
 *  per-user, so the view follows them between workstations. */
export interface SavedView {
  id: number;
  screen: SavedViewScreen;
  name: string;
  query: SavedViewQuery;
  created_at: string | null;
}

// ── Preflight (setup-health) ────────────────────────────────────────────────
// Wave 1's doctor checks, minus the expensive fitness probe, cached
// server-side and exposed as a closed non-admin projection plus an
// admin-only detail read — see soc_ai/api/webui/routes_meta.py.

/** Closed projection any authenticated caller may read: GET /health/preflight.
 *  `status` is 'degraded' iff `failing` > 0 — a WARN never flips it. */
export interface PreflightSummary {
  status: 'green' | 'degraded';
  failing: number;
  warned: number;
  checked_at: string;
}

/** One doctor check's row, as the admin detail read returns it. `status` is
 *  the raw doctor grade ('PASS' | 'WARN' | 'FAIL' | 'INFO'), not narrowed to
 *  the summary's two-state projection. */
export interface PreflightRow {
  name: string;
  status: string;
  detail: string;
  hint: string;
}

/** GET /health/preflight/detail (admin, require_admin_api). */
export interface PreflightDetail {
  rows: PreflightRow[];
  checked_at: string;
}

// ── Audit chain verification (admin) ────────────────────────────────────────
// GET /config/audit/verify-chain (soc_ai/api/webui/routes_config.py) re-runs
// the tamper-evident hash chain check (soc_ai.audit.verify.verify_audit_chain,
// soc_ai.audit.chain.verify_chain) against the live ES audit index — the
// Diagnostics panel's "Verify audit chain" control, and what makes the
// Operate hub's "Audit chain" card promise real.
//
// NOT fail-soft like the checks above: an unreachable or partially-read audit
// index makes the backend RAISE (502/503) rather than answer, so a 200
// response's `ok: false` always means TAMPERED, never "couldn't check" — a
// caller must keep a thrown/rejected call and an `ok: false` result visually
// distinct (never render a request failure as "tampered", and never render
// tampered as success).

/** GET /config/audit/verify-chain (admin, require_admin_api). Mirrors
 *  soc_ai.audit.verify.ChainVerifyResult (+ `checked_at`, stamped by the
 *  route). `first_broken_seq` is non-null iff `ok` is false — that invariant
 *  is enforced server-side by verify_chain's own contract. */
export interface AuditChainVerifyResult {
  ok: boolean;
  records_verified: number;
  first_broken_seq: number | null;
  first_seq: number | null;
  last_seq: number | null;
  capped: boolean;
  checked_at: string;
}
