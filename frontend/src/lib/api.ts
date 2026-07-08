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
  Backtest,
  ChatMessage,
  Config,
  ConnTestResult,
  DangerSetting,
  EntityDetail,
  HuntDetailData,
  HuntRow,
  HuntStat,
  Investigation,
  InvestigationRow,
  Me,
  Notification,
  RehuntResult,
  RepresentativeOut,
  StartBacktestOpts,
  TriageState,
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

/** JSON-body PUT helper. */
function put<T>(path: string, body?: unknown): Promise<T> {
  return request<T>(path, {
    method: 'PUT',
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

/**
 * Lazy-load the events inside one detection group (fetched on row expand).
 * `page` carries `size`/`offset` for "Load more" pagination; omit it for the
 * first page (the backend applies its default page size).
 */
export function getAlertGroupEvents(
  group: Pick<AlertGroup, 'name' | 'kind'>,
  query: AlertQuery = {},
  page?: { size?: number; offset?: number },
): Promise<AlertEvent[]> {
  const base: Record<string, string> = { rule_name: group.name, kind: group.kind };
  if (page?.size != null) base.size = String(page.size);
  if (page?.offset != null) base.offset = String(page.offset);
  const qs = alertQueryParams(query, base);
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

/** Download the audit-grade decision record (JSON with a sha256 integrity checksum). */
export async function downloadInvestigationExport(invId: string): Promise<void> {
  const res = await fetch(`${API_BASE}/investigations/${encodeURIComponent(invId)}/export`, {
    credentials: 'include',
    headers: { Accept: 'application/json' },
  });
  if (!res.ok) throw new Error(`Export failed (${res.status})`);
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `soc-ai-${invId}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// ---------------------------------------------------------------------------
// Hunts (Hunt Console). A Hunt correlates across hosts/time or a free-form
// objective and lands findings + a narrative (read-only in this phase). The
// chat-driven hunt runs on the backend hunt agent; the UI starts it, then polls
// the detail live (mirrors the investigation-hunt flow).
// ---------------------------------------------------------------------------

export function getHunts(): Promise<HuntRow[]> {
  return request<HuntRow[]>('/hunts');
}

export function getHuntStats(): Promise<HuntStat[]> {
  return request<HuntStat[]>('/hunts/stats');
}

export function getHunt(id: string): Promise<HuntDetailData> {
  return request<HuntDetailData>(`/hunts/${encodeURIComponent(id)}`);
}

/**
 * Entity pivot page (E3.5): everything we know about a host/IP — its
 * investigations + hunt findings merged into one newest-first timeline. An
 * unknown entity resolves with an empty timeline (200), not an error.
 * ``value`` may contain dots (IPs) — encoded so the path param captures it whole.
 */
export function getEntity(value: string): Promise<EntityDetail> {
  return request<EntityDetail>(`/entity/${encodeURIComponent(value)}`);
}

/**
 * Start a chat-driven Hunt Console hunt; resolves with the new hunt's id (poll
 * it live). Distinct from ``startHunt``, which starts a single-alert
 * INVESTIGATION — a Hunt Console hunt is broad (findings + narrative).
 */
export function startHuntConsole(
  objective: string,
  priorHuntId?: string,
): Promise<{ hunt_id: string }> {
  return post<{ hunt_id: string }>('/hunts/chat', {
    objective,
    prior_hunt_id: priorHuntId ?? null,
  });
}

/** Cancel an in-flight Hunt Console hunt (marks it cancelled). */
export function cancelHuntConsole(id: string): Promise<{ cancelled: boolean }> {
  return post(`/hunts/${encodeURIComponent(id)}/cancel`);
}

/** Delete a hunt and its events (admin only). 409 if the hunt is still running. */
export function deleteHunt(id: string): Promise<{ deleted: boolean }> {
  return del<{ deleted: boolean }>(`/hunts/${encodeURIComponent(id)}`);
}

/** One message in a hunt's read-only follow-up chat thread. */
export interface HuntChatMessage {
  role: 'user' | 'assistant';
  text: string;
  tools?: string | null;
}

export interface HuntChatThread {
  messages: HuntChatMessage[];
  pending: boolean;
}

/** The hunt's follow-up "Chat about this" thread (poll while pending). */
export function getHuntChat(id: string): Promise<HuntChatThread> {
  return request<HuntChatThread>(`/hunts/${encodeURIComponent(id)}/chat`);
}

/** Ask a read-only follow-up about a completed hunt; returns the updated thread. */
export function postHuntChat(id: string, message: string): Promise<HuntChatThread> {
  return post<HuntChatThread>(`/hunts/${encodeURIComponent(id)}/chat`, { message });
}

// ── Scheduled hunts (E3.1) ──────────────────────────────────────────────────
// A recurring hunt: an objective re-run every ``intervalMinutes`` by the backend
// schedule loop (when the ``hunt_schedules_enabled`` master switch is on), landing
// a normal hunt tagged ``scheduled``. Reads are analyst-readable; mutate is admin.

/** A recurring hunt schedule (interval-minutes, not cron). */
export interface HuntSchedule {
  id: number;
  objective: string;
  intervalMinutes: number;
  enabled: boolean;
  lastRunAt: string | null;
  createdBy: string;
  createdAt: string;
}

/** Create/update payload for a schedule (only provided fields change on update). */
export interface HuntScheduleInput {
  objective: string;
  interval_minutes: number;
  enabled: boolean;
}

/** All recurring hunt schedules, most-recently-created first. */
export function getHuntSchedules(): Promise<HuntSchedule[]> {
  return request<HuntSchedule[]>('/hunt-schedules');
}

/** Create a recurring hunt schedule (admin). */
export function createHuntSchedule(body: HuntScheduleInput): Promise<HuntSchedule> {
  return post<HuntSchedule>('/hunt-schedules', body);
}

/** Update a schedule (admin; only the provided fields change). */
export function updateHuntSchedule(
  id: number,
  body: Partial<HuntScheduleInput>,
): Promise<HuntSchedule> {
  return put<HuntSchedule>(`/hunt-schedules/${id}`, body);
}

/** Delete a schedule (admin). */
export function deleteHuntSchedule(id: number): Promise<{ deleted: boolean }> {
  return del<{ deleted: boolean }>(`/hunt-schedules/${id}`);
}

export function getConfig(): Promise<Config> {
  return request<Config>('/config');
}

/** Model ids the LiteLLM gateway serves — feeds the analyst-model dropdown.
 * ok=false (with a human `detail`) when the gateway can't be listed. */
export function getGatewayModels(): Promise<{ ok: boolean; models: string[]; detail?: string | null }> {
  return request<{ ok: boolean; models: string[]; detail?: string | null }>('/config/models');
}

export interface ModelFitnessLeg {
  name: string;
  ok: boolean;
  grade: 'pass' | 'degraded' | 'fail';
  detail: string;
}

export interface ModelFitness {
  grade: 'pass' | 'degraded' | 'fail';
  model: string;
  legs: ModelFitnessLeg[];
  detail: string;
}

/** Grade whether the configured analyst_model can actually do the pipeline's job
 * (structured output, a tool loop, a budgetable reasoning phase). A model that
 * merely LISTS on the gateway (getGatewayModels) can still be unfit — this runs
 * the real fitness probe and returns the grade for the "Check fitness" chip. */
export function getModelFitness(): Promise<ModelFitness> {
  return request<ModelFitness>('/config/model-fitness');
}

// ── Egress policy (E5.3) — one inspectable page of every egress destination ──

/** One egress destination: its enable state, redaction posture, and a
 * best-effort 7-day audit count (null when the count can't be obtained). */
export interface EgressDestination {
  id: string;
  label: string;
  enabled: boolean;
  redaction: string;
  detail: string;
  count_7d: number | null;
}

export interface EgressPolicy {
  destinations: EgressDestination[];
  /** True iff EVERY destination is disabled — "zero egress" is inspectable. */
  zero_egress: boolean;
}

/** Every possible egress destination, its enable state + redaction posture, and
 * a best-effort 7-day audit counter — so "zero egress" is inspectable, not
 * asserted. Read-only; the counters are best-effort (null when unavailable). */
export function getEgressPolicy(): Promise<EgressPolicy> {
  return request<EgressPolicy>('/config/egress-policy');
}

export interface DataSource {
  id: string;
  name: string;
  category: string;
  egress: string;
  enabled: boolean;
  present: boolean;
  last_refreshed: string | null;
  needs_key: boolean;
  key_configured: boolean;
  note: string;
}

export function getDataSources(): Promise<{ sources: DataSource[] }> {
  return request<{ sources: DataSource[] }>('/config/data-sources');
}

// ── Detection tuning (noisy-rule nomination + soft mutes) ──────────────────

/** A nominated noisy rule from the detection-tuning analysis. */
export interface DetectionNomination {
  rule_name: string;
  alert_count: number;
  investigations: number;
  fp: number;
  tp: number;
  nmi: number;
  recommendation: 'mute' | 'monitor' | 'none';
  reason: string;
  already_muted: boolean;
  /** Analyst-feedback signal (E4.3): how the analyst corrected this rule. */
  override_fp: number;
  chat_resolved: number;
  manual_resolved: number;
}

/** An active operator override (a soft, reversible mute). */
export interface DetectionOverride {
  id: number;
  rule_name: string;
  action: string;
  reason: string | null;
  created_by: string;
  created_at: string;
  active: boolean;
}

export interface DetectionTuning {
  nominations: DetectionNomination[];
  overrides: DetectionOverride[];
}

/** Nominated noisy rules + the active soft-mute overrides. */
export function getDetectionTuning(): Promise<DetectionTuning> {
  return request<DetectionTuning>('/detection-tuning');
}

/** One redacted span: the opaque label, the real value it replaced, and the
 * sanitizer category (IP, HOST, USER, EMAIL, MAC). Safe here because both
 * preview endpoints are admin-gated and already return the raw original. */
export interface RedactionReplacement {
  label: string;
  value: string;
  category: string;
}

export interface RedactionPreview {
  original: Record<string, unknown>;
  sanitized: Record<string, unknown>;
  summary: Record<string, number>;
  /** Pairs that actually occur in THIS preview — drives the pane highlights. */
  replacements: RedactionReplacement[];
  note: string;
}

/** Show exactly what the Oracle pre-egress sanitizer would send (before → after). */
export function getRedactionPreview(): Promise<RedactionPreview> {
  return request<RedactionPreview>('/oracle/redaction-preview');
}

/** Analyst-path redaction preview for one PAST investigation (E5.2). */
export interface AnalystRedactionPreview {
  /** Literal discriminator — pairs with the non-fatal 200 shapes below. */
  status: 'ok';
  investigation_id: string;
  /** Current analyst_cloud_redaction setting — when false the preview is a
   * simulation of what WOULD be redacted, and a real call today sends raw text. */
  redaction_enabled: boolean;
  fail_closed: boolean;
  /** The rebuilt round-1 analyst prompt, composed from the raw stored events. */
  original: string;
  /** The same prompt after the egress guard redacts it (CURRENT identifier config). */
  sanitized: string;
  summary: Record<string, number>;
  /** Pairs that actually occur in THIS preview — drives the pane highlights. */
  replacements: RedactionReplacement[];
  note: string;
}

/** The two non-fatal preview outcomes — HTTP 200 with a status-discriminated
 * body (NOT a 4xx, which would log a browser console error): the investigation
 * exists but its stored events can't honestly rebuild the analyst prompt. */
export interface AnalystRedactionPreviewUnavailable {
  status: 'events_missing' | 'context_unparseable';
  detail: string;
  missing?: string[];
}

/** Discriminated result: "run can't be previewed" is a first-class outcome the
 * panel renders as a friendly note, not an error state. */
export type AnalystRedactionPreviewResult =
  | { kind: 'ok'; preview: AnalystRedactionPreview }
  | { kind: 'events_missing' | 'context_unparseable'; detail: string };

/**
 * What the analyst model would have received for a past investigation —
 * original vs sanitized, rebuilt from its stored events. The endpoint always
 * answers 200 with a `status`-discriminated body (404 only for unknown ids).
 */
export async function getAnalystRedactionPreview(
  invId: string,
): Promise<AnalystRedactionPreviewResult> {
  const token = import.meta.env.VITE_API_TOKEN as string | undefined;
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (token) headers.Authorization = `Bearer ${token}`;
  const res = await fetch(`${API_BASE}/analyst/redaction-preview/${encodeURIComponent(invId)}`, {
    credentials: 'include',
    headers,
  });
  if (!res.ok) throw new Error(`Preview failed (${res.status} ${res.statusText})`);
  const body = (await res.json()) as AnalystRedactionPreview | AnalystRedactionPreviewUnavailable;
  if (body.status !== 'ok') return { kind: body.status, detail: body.detail };
  return { kind: 'ok', preview: body };
}

/** Mute a noisy rule (soft, reversible suppression — Security Onion is untouched). */
export function muteRule(rule_name: string, reason?: string): Promise<DetectionOverride> {
  return post<DetectionOverride>('/detection-tuning/override', {
    rule_name,
    action: 'mute',
    reason: reason ?? null,
  });
}

/** Un-mute a rule by deactivating its override. */
export function unmuteRule(id: number): Promise<{ removed: boolean }> {
  return post<{ removed: boolean }>(`/detection-tuning/override/${id}/remove`);
}

// ── Operator runbooks (the agent's lookup_runbook tool searches these) ─────
export interface Runbook {
  id: number;
  title: string;
  content: string; // markdown / plain text
  tags: string[];
  linked_rules: string[]; // detection rule names / UUIDs this runbook applies to
  created_by: string;
  created_at: string;
  updated_at: string;
  /** Semantic-tier status — BOTH null when the RAG tier is off (rag_embed_model unset). */
  embedded: boolean | null; // a vector exists for this runbook
  stale: boolean | null; // the vector came from a different model than currently configured
}

/** Create/update payload — tags & linked_rules are plain string lists. */
export interface RunbookInput {
  title: string;
  content: string;
  tags: string[];
  linked_rules: string[];
}

/** All operator runbooks, most-recently-updated first. */
export function getRunbooks(): Promise<Runbook[]> {
  return request<Runbook[]>('/runbooks');
}

/** Author a new runbook. */
export function createRunbook(body: RunbookInput): Promise<Runbook> {
  return post<Runbook>('/runbooks', body);
}

/** Update a runbook (only the provided fields change). */
export function updateRunbook(id: number, body: Partial<RunbookInput>): Promise<Runbook> {
  return put<Runbook>(`/runbooks/${id}`, body);
}

/** Delete a runbook. */
export function deleteRunbook(id: number): Promise<{ deleted: boolean }> {
  return del<{ deleted: boolean }>(`/runbooks/${id}`);
}

/** Counts from installing the shipped starter pack (idempotent by title). */
export interface StarterPackResult {
  created: number; // runbooks added this call
  skipped: number; // pack titles already present
}

/** Load the shipped starter-pack runbooks (admin). Safe to re-run — skips
 * any pack runbook whose title already exists, so operator edits survive. */
export function installStarterPack(): Promise<StarterPackResult> {
  return post<StarterPackResult>('/runbooks/starter-pack');
}

// ── Runbook retrieval (RAG) — the opt-in gateway semantic tier (E4.1) ──────
// Default retrieval is local FTS5 (always on, zero egress). When the operator
// configures rag_embed_model, runbook writes embed fail-soft — so vectors can be
// MISSING (gateway was down during a save) or STALE (the model id changed).
// The re-embed endpoint is the catch-up pass; it returns honest counts.

/** Counts from a re-embed pass. `ok` is true iff nothing failed. */
export interface RagReembedResult {
  ok: boolean;
  total: number; // runbooks in the store
  embedded: number; // vectors written this pass
  skipped: number; // already embedded by the current model
  failed: number; // gateway failures (vectors NOT written)
}

/** Embed every runbook whose vector is missing or stale (admin). 400s when
 * rag_embed_model is unset — the semantic tier is off. */
export function reembedRunbooks(): Promise<RagReembedResult> {
  return post<RagReembedResult>('/config/rag/reembed');
}

// ── Hunt templates (curated, telemetry-filtered hunt starters) ─────────────
// A HuntTemplate is a reusable hunt objective the operator picks to seed a new
// hunt — the evolution of the Hunt Console's static "canned pill" strings. The
// list is ANNOTATED with availability against the live grid inventory: a template
// needing telemetry the grid lacks renders FLAGGED (`available=false` +
// `missingDatasets`), never hidden — honesty over hiding.

/** A curated hunt template, annotated with grid availability. */
export interface HuntTemplate {
  id: number;
  name: string;
  objectiveTemplate: string;
  requiredDatasets: string[]; // the event.dataset names this hunt correlates over
  defaultWindowMinutes: number;
  builtin: boolean; // shipped (code-owned) vs operator-saved custom
  createdBy: string;
  createdAt: string;
  available: boolean; // false iff any requiredDataset is absent from the grid
  missingDatasets: string[]; // exactly which telemetry the grid lacks (for the flag)
}

/** Create payload for a custom template (always saved builtin=false). */
export interface HuntTemplateInput {
  name: string;
  objective_template: string;
  required_datasets: string[];
  default_window_minutes?: number;
}

/** All hunt templates, builtins first, annotated with grid availability. */
export function getHuntTemplates(): Promise<HuntTemplate[]> {
  return request<HuntTemplate[]>('/hunt-templates');
}

/** Save a custom hunt template (admin). */
export function createHuntTemplate(body: HuntTemplateInput): Promise<HuntTemplate> {
  return post<HuntTemplate>('/hunt-templates', body);
}

/** Delete a custom hunt template (admin; a builtin returns 409). */
export function deleteHuntTemplate(id: number): Promise<{ deleted: boolean }> {
  return del<{ deleted: boolean }>(`/hunt-templates/${id}`);
}

// ── API keys (write-only enrichment provider secrets) ──────────────────────
export interface ApiKeyField {
  key: string;
  label: string;
  help: string;
  isSet: boolean;
  source: string; // "db" | "env" | "unset"
}

export function getApiKeys(): Promise<ApiKeyField[]> {
  return request<ApiKeyField[]>('/config/api-keys');
}

export function saveApiKey(key: string, value: string): Promise<{ ok: boolean; isSet: boolean }> {
  return post<{ ok: boolean; isSet: boolean }>('/config/api-keys', { key, value });
}

export function clearApiKey(key: string): Promise<{ ok: boolean; isSet: boolean }> {
  return del<{ ok: boolean; isSet: boolean }>(`/config/api-keys/${encodeURIComponent(key)}`);
}

// ── Notifications (E2.4): the webhook secret + a "Send test" validation ─────
// The master toggle / per-trigger toggles / format / threshold are ordinary
// settings in the "Notifications" config group. The webhook URL is a secret
// (write-only, Fernet-encrypted) on its own endpoints so it renders in the
// Notifications section, not the shared API-keys panel.
export interface NotifyWebhookStatus {
  isSet: boolean;
  source: string; // "db" | "env" | "unset"
}

export function getNotifyWebhook(): Promise<NotifyWebhookStatus> {
  return request<NotifyWebhookStatus>('/config/notify/webhook');
}

export function saveNotifyWebhook(value: string): Promise<{ ok: boolean; isSet: boolean }> {
  return post<{ ok: boolean; isSet: boolean }>('/config/notify/webhook', { value });
}

export function clearNotifyWebhook(): Promise<{ ok: boolean; isSet: boolean }> {
  return del<{ ok: boolean; isSet: boolean }>('/config/notify/webhook');
}

/** Send a canned, synthetic test notification. Requires a configured webhook URL
 * but NOT the master toggle, so the operator can validate the destination before
 * enabling routing. Returns {ok, detail} — detail is scrubbed (never the URL). */
export function testNotifyWebhook(): Promise<ConnTestResult> {
  return post<ConnTestResult>('/config/notify/test');
}

// ── Agent tools (capabilities + dependency availability) ───────────────────
export interface AgentTool {
  name: string;
  category: string;
  read_only: boolean;
  description: string;
  requires: string[];
  missing: string[];
  available: boolean;
}

export function getAgentTools(): Promise<{ tools: AgentTool[] }> {
  return request<{ tools: AgentTool[] }>('/config/agent-tools');
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

/** Cancel an in-flight hunt (lands the run as `cancelled`). 404 if not running. */
export function cancelHunt(invId: string): Promise<{ cancelled: boolean }> {
  return post<{ cancelled: boolean }>(`/investigations/${invId}/cancel`);
}

/**
 * Launch a FOCUSED re-investigation to close a `needs_more_info` verdict.
 *
 * Re-runs the investigation on the same alert but seeds the fresh run with the
 * prior open questions, so it targets those gaps. Resolves to the new INV id
 * (navigate + poll it like a re-hunt). 409 if the source verdict isn't
 * `needs_more_info`.
 */
export function requestMoreInfo(invId: string): Promise<string> {
  return post<{ investigation_id: string }>(
    `/investigations/${encodeURIComponent(invId)}/request-more-info`,
  ).then((r) => r.investigation_id);
}

/** Delete an investigation and its events + chat (admin only). */
export function deleteInvestigation(invId: string): Promise<{ deleted: boolean }> {
  return del<{ deleted: boolean }>(`/investigations/${invId}`);
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
  // Per-reason breakdown of `skipped` (reason code → count); sums to `skipped`.
  skipped_reasons?: Record<string, number>;
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

/** Request the running auto-triage batch to stop after the current target. */
export function stopAutoTriage(): Promise<AutoTriageStatus> {
  return post<AutoTriageStatus>('/auto-triage/stop');
}

// ── Backtest ("prove it on my last N days") ─────────────────────────────────

/** Launch a background backtest: replay soc-ai's triage over a sample of
 *  already-dispositioned alerts and score its verdicts against the analyst's
 *  real Security Onion disposition. Admin-gated + expensive (each sample is a
 *  full investigation); the backend clamps sampleSize to its hard cap. */
export function startBacktest(opts: StartBacktestOpts): Promise<Backtest> {
  const body: Record<string, unknown> = {
    window_days: opts.windowDays,
    sample_size: opts.sampleSize,
  };
  if (opts.minSeverity) body.min_severity = opts.minSeverity;
  return post<Backtest>('/backtest', body);
}

/** The current/last backtest — live progress while running, results when done. */
export function getBacktest(): Promise<Backtest> {
  return request<Backtest>('/backtest');
}

/** A specific backtest run by id. */
export function getBacktestById(id: string): Promise<Backtest> {
  return request<Backtest>(`/backtest/${encodeURIComponent(id)}`);
}

export interface AckGroupResult {
  acked: number;
  failed: number;
  total: number;
  capped: boolean;
}

export interface EscalateGroupResult {
  escalated: number;
  failed: number;
  total: number;
  capped: boolean;
}

export interface AssignResult {
  rule_name: string;
  owner: string | null;
  state?: TriageState | null;
}

/**
 * Assign (or unassign) the logged-in caller as owner of a detection rule, or
 * move an already-owned rule through the triage flow (E2.3).
 *
 * - `assignAlert(rule)` → assign the caller (state resets to "owned").
 * - `assignAlert(rule, true)` → unassign (owner + state cleared).
 * - `assignAlert(rule, false, "in_review")` → set the triage state on an
 *   already-owned rule (owner unchanged). 404s if the rule has no owner.
 *
 * Returns the persisted owner + state (both null after unassign).
 */
export function assignAlert(
  ruleName: string,
  unassign = false,
  state?: TriageState,
): Promise<AssignResult> {
  return post<AssignResult>('/alerts/assign', {
    rule_name: ruleName,
    unassign,
    ...(state ? { state } : {}),
  });
}

/** Acknowledge all events for a detection group via the SO ack_alert write tool. */
export function ackGroup(
  group: Pick<AlertGroup, 'name' | 'kind'>,
  query: AlertQuery = {},
): Promise<AckGroupResult> {
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

/**
 * Escalate all events for a detection group to Security Onion cases via the
 * escalate_to_case write tool. Sibling of {@link ackGroup} — same body shape
 * and filters; the backend caps how many cases a single call may open.
 */
export function escalateGroup(
  group: { name: string; kind: string },
  query: AlertQuery = {},
): Promise<EscalateGroupResult> {
  const body: Record<string, string | undefined> = { rule_name: group.name, kind: group.kind };
  if (query.range === 'custom' && query.from && query.to) {
    body.from_ = query.from;
    body.to = query.to;
  } else if (query.range) {
    body.range = query.range;
  }
  if (query.severity) body.severity = query.severity;
  return post<EscalateGroupResult>('/alerts/escalate-group', body);
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

/**
 * Dismiss a DETECTED identifier suggestion for good — it vanishes from the list
 * (re-add manually to restore). Distinct from muting (which keeps the row but
 * unused). Throws (409) for a manual row — use removeIdentifier (DELETE) there.
 */
export function dismissIdentifier(id: number): Promise<{ ok: boolean }> {
  return post<{ ok: boolean }>(`/internal-identifiers/${id}/dismiss`, {});
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
    // Keep generic — don't leak whether the username exists.
    throw new Error('Invalid username or password');
  }
  if (!res.ok) {
    // Surface the server's helpful detail/hint (e.g. a 429 rate-limit message)
    // rather than collapsing every non-401 failure into a credentials error.
    let detail = `Login failed: ${res.status} ${res.statusText}`;
    try {
      const body = await res.json();
      const hint = body?.detail?.hint ?? (typeof body?.detail === 'string' ? body.detail : null);
      if (hint) detail = hint;
    } catch {
      /* non-JSON error body — keep the status line */
    }
    throw new Error(detail);
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

/**
 * Sign out: destroy the server session, then route to /login.
 * Shared by the sidebar and command palette so they can't drift — a bare
 * client-side navigate would leave the session cookie alive (security bug).
 */
export function signOut(navigate: (to: string) => void): Promise<void> {
  return logout().finally(() => navigate('/login'));
}
