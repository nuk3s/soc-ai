// ---------------------------------------------------------------------------
// Data-access boundary. ALL screen data flows through these async functions.
//
// Today they resolve mock data. In the next increment each body is swapped for a
// fetch() against the FastAPI JSON API — the function signatures and return
// types stay identical, so no screen has to change. Screens MUST consume these
// asynchronously (loading / empty / error states) and never import ./mock.
// ---------------------------------------------------------------------------

import type {
  AboutInfo,
  AdminUser,
  AlertEvent,
  AlertGroup,
  Backtest,
  ChatMessage,
  Config,
  ConnTestResult,
  DangerSetting,
  Dossier,
  DossierConflicts,
  DossierFieldName,
  DossierHealthFilter,
  DossierLane,
  DossierList,
  DossierRefreshStatus,
  DossierSortKey,
  DossierSummary,
  EntityDetail,
  HostActivity,
  HostActivityRange,
  HuntBulkDeleteResult,
  HuntDetailData,
  HuntRehuntResult,
  HuntRow,
  HuntStat,
  Investigation,
  InvestigationList,
  InvestigationRow,
  Me,
  Notification,
  RehuntResult,
  RepresentativeOut,
  SavedView,
  SavedViewQuery,
  SavedViewScreen,
  StartBacktestOpts,
  TriageState,
  UpdateCheckResult,
  Workspace,
} from './types';

/** JSON-body POST helper. */
function post<T>(path: string, body?: unknown, opts?: RequestOpts): Promise<T> {
  return request<T>(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
    ...opts,
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
function del<T>(path: string, opts?: RequestOpts): Promise<T> {
  return request<T>(path, { method: 'DELETE', ...opts });
}

// ---------------------------------------------------------------------------
// Real API plumbing. Endpoints that have been wired to the FastAPI JSON API
// (/api/v1) use request(); the rest still resolve mock data above until their
// increment lands. Same-origin in prod (served under /app), so the session
// cookie flows; a VITE_API_TOKEN bearer is used in cross-origin dev.
// ---------------------------------------------------------------------------
const API_BASE = '/api/v1';

/** Where the analyst was when their session expired — login reads this to
 *  return them to their deep link instead of always landing on the dashboard.
 *  A ?next= param carries the same value as a fallback when sessionStorage is
 *  unavailable. */
export const POST_LOGIN_REDIRECT_KEY = 'soc-ai:post-login-redirect';

/** The SPA's own path prefix ('/app'), i.e. the router basename main.tsx uses. */
const APP_BASE = import.meta.env.BASE_URL.replace(/\/$/, '');

/**
 * A stored destination, reduced to a router path — or null if it is not one.
 *
 * The value comes back from sessionStorage or a ?next= query param, and both
 * are writable by whoever can hand the analyst a link. So this is an
 * allow-list, not a deny-list: the ONLY thing accepted is a path that already
 * begins with the SPA's own prefix. That single rule refuses every open-redirect
 * shape at once — `https://evil.example/x` and `javascript:…` don't start with
 * a slash at all, and `//evil.example/x` (protocol-relative, the one that looks
 * like a path) is refused by the explicit check below because a bare
 * `startsWith('/')` would wave it through if BASE_URL were ever '/'.
 *
 * `/app/login` is refused too: honouring it would return the analyst to the
 * screen they just left, which reads as a failed sign-in. That check compares
 * the way the ROUTER matches — case-folded and without the query or fragment —
 * because `/app/LOGIN` and `/app/login#x` reach the Login screen just as surely
 * as the lower-case spelling does, and a check that only knew one of them would
 * be a rule the other two walk around.
 *
 * The return value drops the prefix, because react-router's navigate() works
 * inside the basename — passing the browser path would land on /app/app/hosts.
 */
function inAppPath(raw: string | null | undefined): string | null {
  if (!raw) return null;
  // Protocol-relative and backslash-smuggled authorities, before anything else.
  if (raw.startsWith('//') || raw.startsWith('/\\')) return null;
  if (!raw.startsWith(APP_BASE + '/')) return null;
  const path = raw.slice(APP_BASE.length);
  const route = path.toLowerCase().split(/[?#]/)[0];
  if (route === '/login' || route.startsWith('/login/')) return null;
  return path;
}

/**
 * Consume the deep link a 401 stashed, if there is a usable one.
 *
 * Reading it CLEARS it, whether or not it survived {@link inAppPath}: a
 * destination is good for exactly one sign-in, and a rejected one must not sit
 * in storage waiting for the next. Returns a router-relative path, or null for
 * "no destination" — the caller decides the default.
 */
export function takePostLoginRedirect(search?: string): string | null {
  let stored: string | null = null;
  try {
    stored = sessionStorage.getItem(POST_LOGIN_REDIRECT_KEY);
    sessionStorage.removeItem(POST_LOGIN_REDIRECT_KEY);
  } catch {
    /* storage blocked — the ?next= param below is exactly this fallback */
  }
  const fromStorage = inAppPath(stored);
  if (fromStorage) return fromStorage;
  const qs = search ?? (typeof window === 'undefined' ? '' : window.location.search);
  return inAppPath(new URLSearchParams(qs).get('next'));
}

/**
 * A non-OK API response, carrying the HTTP status the screens branch on.
 *
 * "This run doesn't exist" and "the grid is down" are different answers, and
 * with only a message string to go on every detail screen rendered them as the
 * same alarm-red card (dogfood B3, 2026-08-11). Transport failures — network
 * error, client timeout — stay plain `Error`s: they carry no status because
 * there was no response, and "not found" is exactly what they cannot claim.
 */
export class ApiError extends Error {
  readonly status: number;
  /**
   * House error code (e.g. `bad_credentials`), when the body carried one. The
   * wire shape is {reason, hint}: `hint` is the sentence shown to the analyst,
   * `reason` the machine-readable code. Callers key off `reason` — matching the
   * prose instead breaks the moment the wording is edited, and can't separate
   * two rejections that read alike.
   */
  readonly reason?: string;

  constructor(message: string, status: number, reason?: string) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.reason = reason;
  }
}

/** True when a request failed because the thing it asked for isn't there. */
export function isNotFound(error: unknown): boolean {
  return error instanceof ApiError && error.status === 404;
}

/**
 * Hand a mid-session 401 off to the login page without throwing the analyst's
 * place away. The Topbar polls every 15s, so expiry on a long-lived tab trips
 * this from a background request — capture the current deep link (sessionStorage
 * + a ?next= param) so login can restore it, and don't re-navigate when we're
 * already on the login screen (a stray poll must not clobber a sign-in attempt).
 */
function redirectToLogin(): void {
  if (window.location.pathname.replace(/\/+$/, '') === '/app/login') return;
  const next = window.location.pathname + window.location.search + window.location.hash;
  try {
    sessionStorage.setItem(POST_LOGIN_REDIRECT_KEY, next);
  } catch {
    /* storage blocked — the ?next= param still carries the destination */
  }
  window.location.href = '/app/login?next=' + encodeURIComponent(next);
}

// Client-side budget for every JSON request. Without it, fetch inherits the
// browser default (effectively indefinite) — and when the backend hangs on a
// down Elasticsearch (~90s worst case), stacked polls exhaust the browser's
// ~6-connections-per-origin pool, so even DB-backed widgets and lazy route
// chunks queue behind hung requests and the whole UI appears frozen (dogfood
// 2026-08-05). 20s sits above the backend's 12s grid bound; callers with a
// known-slow endpoint can pass their own timeoutMs. Streaming (SSE) paths do
// NOT go through this helper — a total-duration signal would kill them.
const REQUEST_TIMEOUT_MS = 20_000;

/**
 * Per-call overrides the fetch helpers forward to `request()`.
 *
 * `skipLoginRedirect` is for the handful of endpoints where a 401 is an
 * ANSWER rather than an expiry — see the saved-view calls at the bottom of this
 * file. Everything else keeps the global handoff, so a session that really did
 * expire still lands on login with its deep link intact.
 */
interface RequestOpts {
  timeoutMs?: number;
  skipLoginRedirect?: boolean;
}

async function request<T>(path: string, init?: RequestInit & RequestOpts): Promise<T> {
  const token = import.meta.env.VITE_API_TOKEN as string | undefined;
  const headers: Record<string, string> = { Accept: 'application/json' };
  if (init?.headers) Object.assign(headers, init.headers as Record<string, string>);
  if (token) headers.Authorization = `Bearer ${token}`;

  let res: Response;
  try {
    res = await fetch(API_BASE + path, {
      credentials: 'include',
      signal: AbortSignal.timeout(init?.timeoutMs ?? REQUEST_TIMEOUT_MS),
      ...init,
      headers,
    });
  } catch (e) {
    if (e instanceof DOMException && e.name === 'TimeoutError') {
      throw new Error('Request timed out — the soc-ai API (or Security Onion behind it) is slow or down.');
    }
    throw new Error('Network error — is the soc-ai API reachable?');
  }

  if (res.status === 401 && !init?.skipLoginRedirect) {
    // Not authenticated / session expired — hand off to the login page,
    // preserving the analyst's current deep link (see redirectToLogin).
    // Opted-out callers fall through to the ApiError below instead, so they
    // can read the refusal rather than have the page navigated out from under
    // them (RequestOpts.skipLoginRedirect).
    redirectToLogin();
    throw new Error('Unauthorized');
  }
  if (!res.ok) {
    let detail = `${res.status} ${res.statusText}`;
    let reason: string | undefined;
    try {
      const body = await res.json();
      const hint = body?.detail?.hint ?? (typeof body?.detail === 'string' ? body.detail : null);
      if (hint) detail = hint;
      // The house error shape is {reason, hint}: `hint` is the sentence shown to
      // the analyst, `reason` the machine-readable code. Dropping `reason` forced
      // callers to regex the prose to work out WHAT failed — which breaks the
      // moment the wording is edited, and can't separate two rejections that read
      // alike. Carry it on the Error instead.
      if (typeof body?.detail?.reason === 'string') reason = body.detail.reason;
    } catch {
      /* non-JSON error body — keep the status line */
    }
    throw new ApiError(detail, res.status, reason);
  }
  return (await res.json()) as T;
}

export interface AlertQuery {
  range?: string; // a preset ('24h') or 'custom'
  from?: string; // datetime-local, when range === 'custom'
  to?: string;
  severity?: string; // '' = all, else critical|high|medium|low
  hideAcked?: boolean; // when true, exclude acknowledged/escalated groups
  /** An OQL filter clause, validated server-side (parse + field whitelist).
   *  Carried by deep links — the host page's Alerts KPI narrows this screen to
   *  one host with it. Part of AlertQuery so the event pages and group actions
   *  fetched under an active filter stay scoped to the same set. */
  q?: string;
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
  if (query.q) p.set('q', query.q);
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

/** Filters for the investigations list — applied by the SERVER, in SQL.
 * `verdict` accepts the stored verdicts plus the synthetic 'pipeline_error'
 * (fallback-marked runs); `status` accepts the display statuses. Both are
 * multi-value (joined as comma-separated params). */
export interface InvestigationListQuery {
  since?: string;
  until?: string;
  verdict?: string[];
  status?: string[];
  /** Free text, matched SERVER-side against rule name, source and destination.
   *  Client-side filtering is what made older runs unreachable in the first
   *  place — see the note above. */
  q?: string;
  limit?: number;
  offset?: number;
}

/** One filtered, counted, paged slice of the investigations list. */
export function listInvestigations(q: InvestigationListQuery = {}): Promise<InvestigationList> {
  const p = new URLSearchParams();
  if (q.since) p.set('since', q.since);
  if (q.until) p.set('until', q.until);
  if (q.verdict?.length) p.set('verdict', q.verdict.join(','));
  if (q.status?.length) p.set('status', q.status.join(','));
  if (q.q?.trim()) p.set('q', q.q.trim());
  if (q.limit != null) p.set('limit', String(q.limit));
  if (q.offset != null) p.set('offset', String(q.offset));
  const qs = p.toString();
  return request<InvestigationList>(`/investigations${qs ? `?${qs}` : ''}`);
}

/** The newest rows, unfiltered (first page) — for the two consumers that want a
 * recent sample rather than a query: the command palette's jump list and the
 * redaction-preview picker. Anything that reports a FIGURE wants
 * `listInvestigations` and its server-side counts; a sample counted as if it
 * were a query is how the pipeline-error KPI came to read zero. */
export function getInvestigations(): Promise<InvestigationRow[]> {
  return listInvestigations({ limit: 100 }).then((r) => r.rows);
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
    signal: AbortSignal.timeout(60_000),
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

export interface HuntsQuery {
  since?: string; // ISO datetime — inclusive lower bound on created_at
  until?: string; // ISO datetime — inclusive upper bound on created_at
}

export function getHunts(query: HuntsQuery = {}): Promise<HuntRow[]> {
  const p = new URLSearchParams();
  if (query.since) p.set('since', query.since);
  if (query.until) p.set('until', query.until);
  const qs = p.toString();
  return request<HuntRow[]>('/hunts' + (qs ? `?${qs}` : ''));
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
 * The longest objective the hunt endpoints accept (MAX_OBJECTIVE_CHARS in
 * routes_hunts.py). Lives at the API boundary because the two callers are on
 * opposite sides of the app: the Hunt Console's textarea hard-stops here, and
 * the Dashboard chat clamps an agent-written objective here — a proposal card
 * that 422s on click is worse than one that was trimmed.
 */
export const MAX_OBJECTIVE_CHARS = 12000;

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

/**
 * Re-run a set of hunts as CLEAN fresh hunts of the same objective (no
 * prior-narrative seeding). The batch is throttled server-side: only the first
 * few are STARTED, the rest come back skipped/"queued" — re-hunt those in a
 * smaller follow-up batch. Distinct from ``rehuntInvestigations`` (single-alert).
 */
export function rehuntHunts(huntIds: string[]): Promise<HuntRehuntResult> {
  return post<HuntRehuntResult>('/hunts/rehunt', { hunt_ids: huntIds });
}

/** Delete a set of hunts (admin only). Running hunts are reported not-removed. */
export function bulkDeleteHunts(huntIds: string[]): Promise<HuntBulkDeleteResult> {
  return post<HuntBulkDeleteResult>('/hunts/bulk-delete', { hunt_ids: huntIds });
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
  /** Tools the in-flight turn has called so far, oldest first (empty when idle). */
  progress_tools?: string[];
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

/** Schedule rows plus the ``hunt_schedules_enabled`` global master switch — off
 * means no schedule fires no matter what its own per-row `enabled` says. */
export interface HuntScheduleList {
  schedules: HuntSchedule[];
  masterSwitchEnabled: boolean;
}

/** All recurring hunt schedules, most-recently-created first, plus master-switch state. */
export function getHuntSchedules(): Promise<HuntScheduleList> {
  return request<HuntScheduleList>('/hunt-schedules');
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
  /** How slow, and on which backend. Null on a leg that never ran far enough to
   * measure, and on verdicts cached before the 2026-08-07 probe rebuild. */
  elapsed_s?: number | null;
  backend?: string | null;
}

export interface ModelFitness {
  /** 'unknown' = no probe ran and there was no cached verdict to carry over. */
  grade: 'pass' | 'degraded' | 'fail' | 'unknown';
  model: string;
  legs: ModelFitnessLeg[];
  detail: string;
  /** true = served from the 24h server-side cache (checked_at = when measured). */
  cached?: boolean;
  checked_at?: string | null;
  /** Which gateway backend actually served the probe. soc-ai asks for an ALIAS
   * and the gateway may route it anywhere, so without this "model X is unfit"
   * names what we asked for rather than what ran. */
  served_backend?: { api_base: string } | null;
  /** false = the self-load guard declined to probe (soc-ai's own eval /
   * auto-triage / battery was saturating the same gateway); `note` says why and
   * any verdict shown alongside is the previous, cached one. */
  measured?: boolean;
  note?: string | null;
  /** THE red-state boolean: two consecutive failed checks. A single fail is a
   * measurement, not a verdict — the chip's colour keys on this, never on
   * `grade === 'fail'`. All the history fields below are null when the audit
   * store could not be read, where `alarm` degrades to the single sample. */
  alarm?: boolean;
  recent_checks?: number | null;
  recent_fails?: number | null;
  consecutive_fails?: number | null;
  last_pass_at?: string | null;
}

/** Grade whether the configured analyst_model can actually do the pipeline's job
 * (structured output, a tool loop, a budgetable reasoning phase). A model that
 * merely LISTS on the gateway (getGatewayModels) can still be unfit — this runs
 * the real fitness probe and returns the grade for the "Check fitness" chip. */
export function getModelFitness(force = false): Promise<ModelFitness> {
  return request<ModelFitness>(`/config/model-fitness${force ? '?force=true' : ''}`);
}

// ── Model fitness battery (design spec 2026-08-05) ──────────────────────────

export interface BatteryConfigResult {
  output_mode: 'tool' | 'native' | 'prompted';
  tool_choice_required: boolean;
  ok: number;
  n: number;
  usable_rate: number;
  tally: Record<string, number>;
  failures: string[];
  elapsed_s: number;
}

export interface BatteryRecommendation {
  synthesizer_output_mode: 'tool' | 'native' | 'prompted';
  analyst_tool_choice_required: boolean;
  config: string;
  reason: string;
}

export interface BatteryResult {
  model: string;
  n_per_config: number;
  configs: BatteryConfigResult[];
  recommendation: BatteryRecommendation | null;
  elapsed_s: number;
}

export interface ModelBatteryStatus {
  running: boolean;
  model: string;
  current_config: string | null;
  completed: number;
  total: number;
  error?: string | null;
  result: BatteryResult | null;
  stored_at: string | null;
}

/** Live battery progress while one runs; otherwise the persisted last result
 * (with its timestamp) for the requested model. */
export function getModelBattery(model: string): Promise<ModelBatteryStatus> {
  return request<ModelBatteryStatus>(
    `/config/model-battery?model=${encodeURIComponent(model)}`,
  );
}

/** Start the full fitness battery for a model in the background (409 while one
 * is already running — single-flight so timings stay attributable). */
export function startModelBattery(model: string): Promise<{ started: boolean; model: string }> {
  return request<{ started: boolean; model: string }>('/config/model-battery', {
    method: 'POST',
    body: JSON.stringify({ model }),
  });
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

// ── Quality trend (I4) — the nightly micro-eval history for the Quality card ──

/** One `soc-ai eval-nightly` snapshot. `mode` labels the instrument: `graded`
 * points carry an oracle `agreement_rate`; `local` points are zero-egress and
 * lean on the fallback/error-rate proxies (`agreement_rate` is null there —
 * an honest "not measured", never 0). `alarmed`/`alarm_reasons` are the
 * regression-detector verdict persisted at write time. */
export interface QualityPoint {
  id: number;
  ts: string;
  mode: 'local' | 'graded';
  n_ok: number;
  n_error: number;
  agreement_rate: number | null;
  /** The grade counts behind `agreement_rate` (= `n_yes / n_classified`). All
   * four are null on rows written before migration 0026 and stay that way
   * forever — nothing can recover them — so every reader must treat null as
   * "never recorded", not as 0. A `partial` critique ("right verdict, thin
   * reasoning") lands in `n_classified` but not `n_yes`, which is why the rate
   * alone can't tell 3 agree + 2 partial from 3 agree + 2 wrong. */
  n_yes: number | null;
  n_partial: number | null;
  n_no: number | null;
  n_classified: number | null;
  fallback_rate: number | null;
  error_rate: number;
  latency_p50_ms: number | null;
  verdict_counts: Record<string, number>;
  alarmed: boolean;
  alarm_reasons: string[];
  /** WHICH condition alarmed (migration 0027): `agreement_drop`,
   * `error_ceiling`, `fallback_jump`. `alarm_reasons` above can't answer that —
   * each message bakes in the run's live numbers, so the same condition reads
   * differently every night. Empty on a clean point AND on a pre-0027 row,
   * where the condition was never recorded; readers must render the prose in
   * that case rather than infer a code.
   *
   * All three are OPTIONAL, not merely nullable, because a server older than
   * this release omits them from the JSON entirely — an SPA build outliving its
   * backend (or a cached bundle) must parse that response, not crash on it. */
  alarm_codes?: string[];
  /** The codes sorted and joined with "+" — the identity of one alarm
   * CONDITION, so `agreement_drop+error_ceiling` on two nights is one problem
   * and not two. Null when clean or pre-0027. */
  alarm_key?: string | null;
  /** ISO-8601 (tz-aware) start of the CURRENT condition. Earlier than the
   * point's own `ts` means the alarm is ongoing, not newly raised — the
   * difference between "this keeps firing" and "this is still true". Null when
   * clean or pre-0027. */
  alarm_since?: string | null;
  /** Server-side directory holding this run's eval bundle — the oracle
   * critiques that are the only evidence for or against an alarm. A filesystem
   * path on the soc-ai host, NOT a URL: no endpoint serves it. Null on rows
   * written before migration 0026. */
  batch_dir: string | null;
}

export interface QualityTrend {
  /** Oldest → newest (server-ordered), ready to plot left-to-right. */
  points: QualityPoint[];
}

/** The last 30 nightly quality snapshots (admin-gated, like the other posture
 * read-models). Empty points = the nightly has never run on this install. */
export function getQualityTrend(): Promise<QualityTrend> {
  return request<QualityTrend>('/quality/trend');
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
    signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
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
  /** Unapproved machine-authored promotion draft — excluded from agent retrieval until approved. */
  draft: boolean;
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

// ── Runbook promotion — draft org-specific runbooks from investigation history ─
// The deployment already knows how each rule's alerts resolved here (verdicts,
// rationales, analyst chat). Promotion distills that into a DRAFT runbook the
// operator reviews in this page. Drafts are invisible to agent retrieval until
// approved — nothing auto-applies.

/** One rule with enough completed investigation history to distill. */
export interface PromotableRule {
  rule_name: string;
  investigations: number; // completed, verdict-bearing, non-fallback
  false_positive: number;
  true_positive: number;
  needs_more_info: number;
  dominant_verdict: string;
  last_activity: string; // ISO-8601 of the newest counted investigation
}

/** Rules promotable into a draft runbook (admin). Cheap local read. */
export function getPromotableRules(): Promise<PromotableRule[]> {
  return request<PromotableRule[]>('/runbooks/promotable');
}

/** Distill one rule's history into a DRAFT runbook (admin). SYNCHRONOUS —
 * one analyst-model call, typically seconds to ~a minute; show progress. */
export function promoteRunbook(rule_name: string): Promise<Runbook> {
  return post<Runbook>('/runbooks/promote', { rule_name });
}

/** Approve a draft (admin): makes it retrievable by the agent and embeds it
 * when the semantic tier is on. */
export function approveRunbook(id: number): Promise<Runbook> {
  return post<Runbook>(`/runbooks/${id}/approve`);
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
  // Was `available` MEASURED? When the grid inventory could not be read the
  // server still reports available=true — fail-open, so an unreadable inventory
  // never hides or falsely flags a hunt — and this says so, because on the wire
  // a fail-open default and a measured yes are otherwise identical. The picker
  // renders a third, neutral state off it rather than the confident chip.
  // Optional so a payload from a server predating the flag reads as "known",
  // which is what it was.
  availabilityKnown?: boolean;
  // Environment fit — a SECOND, independent axis. `available` says the grid can
  // SEE the telemetry; `applicable` says the network HAS the machinery the hunt
  // targets (a Windows host, a domain), from the resolved dossiers. false → the
  // picker DEMOTES the chip into a collapsed cluster, never hides it, and it
  // stays fully runnable. Fail-open server-side: custom templates, profile
  // errors and a never-built dossier table all report true.
  applicable: boolean;
  missingEnvironment: string[]; // human phrases, e.g. "a domain-joined host"
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

/** Build metadata (version, repo, license) plus the feature flags a screen needs
 *  before it renders — see `AboutInfo`, which is the whole contract. */
export function getAbout(): Promise<AboutInfo> {
  return request<AboutInfo>('/about');
}

/** Manually compare the running version to the latest GitHub release (admin,
 * opt-in). Never rejects on an unreachable GitHub — the result carries the
 * failure in `ok`/`detail`. */
export function checkForUpdates(): Promise<UpdateCheckResult> {
  return post<UpdateCheckResult>('/updates/check');
}

// ---- mutations ------------------------------------------------------------

/** Start a background investigation for an alert; resolves to the new INV id.
 * `deep` forces the full tool-driven loop for this run — the "deep re-run"
 * of a heuristic (zero-tool) verdict. */
export function startHunt(alertId: string, opts?: { deep?: boolean }): Promise<string> {
  return post<{ investigation_id: string }>('/hunt', {
    alert_id: alertId,
    ...(opts?.deep ? { deep: true } : {}),
  }).then((r) => r.investigation_id);
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

/**
 * Acknowledge a pipeline-error run so the Dashboard KPI stops counting it.
 * The run stays a fallback historically (Pipeline-error filter still shows it);
 * only the dashboard nag is silenced. Idempotent; 409 if the run isn't a
 * pipeline fallback.
 */
export function dismissInvestigationError(invId: string): Promise<{ ok: boolean }> {
  return post<{ ok: boolean }>(`/investigations/${encodeURIComponent(invId)}/dismiss-error`, {});
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
  /** Tools the in-flight turn has called so far, oldest first (empty when idle). */
  progress_tools?: string[];
}

export function getChatThread(invId: string): Promise<ChatThread> {
  return request<ChatThread>(`/investigations/${encodeURIComponent(invId)}/chat`);
}

export function postChat(invId: string, message: string): Promise<ChatThread> {
  return post<ChatThread>(`/investigations/${encodeURIComponent(invId)}/chat`, { message });
}

// ── The Dashboard's general chat ────────────────────────────────────────────
// One rolling thread per analyst, keyed server-side on the caller's identity —
// which is why these three take no id. They return the SAME `ChatThread` shape
// as the investigation chat (the backend serializes every chat surface through
// one serializer), so `useChatThread` drives this surface unchanged.

/** This analyst's dashboard thread; also the poll target while a turn runs. */
export function getGeneralChat(): Promise<ChatThread> {
  return request<ChatThread>('/chat');
}

/** Ask the dashboard assistant. 409 while a turn is already in flight. */
export function postGeneralChat(message: string): Promise<ChatThread> {
  return post<ChatThread>('/chat', { message });
}

/** Discard this analyst's thread. Resolves with it empty, so the caller can
 *  reuse the same response handler it uses for a GET. */
export function clearGeneralChat(): Promise<ChatThread> {
  return del<ChatThread>('/chat');
}

// ── The host page chat ──────────────────────────────────────────────────────
// One SHARED thread per host, keyed server-side on the address ("host:<ip>") —
// the investigation-chat precedent for object-scoped chats, so every analyst on
// this host's page reads the same conversation. Same `ChatThread` wire shape as
// every other chat surface (one backend serializer), so `useChatThread` drives
// it unchanged.

/** This host's shared thread; also the poll target while a turn runs. */
export function getHostChat(ip: string): Promise<ChatThread> {
  return request<ChatThread>(`/dossiers/${encodeURIComponent(ip)}/chat`);
}

/** Ask about this host. 409 while a turn is already in flight on its thread. */
export function postHostChat(ip: string, message: string): Promise<ChatThread> {
  return post<ChatThread>(`/dossiers/${encodeURIComponent(ip)}/chat`, { message });
}

/** Discard this host's thread (this host's only). Resolves with it empty. */
export function clearHostChat(ip: string): Promise<ChatThread> {
  return del<ChatThread>(`/dossiers/${encodeURIComponent(ip)}/chat`);
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

/**
 * Change your own password. Rejections (wrong current password, below the
 * server's minimum length) arrive as a thrown Error carrying the backend's
 * hint, which the modal renders inline. On success the caller stays signed in —
 * the backend keeps THIS session and drops the account's others.
 */
export function changePassword(
  currentPassword: string,
  newPassword: string,
): Promise<{ ok: boolean }> {
  return post<{ ok: boolean }>('/me/password', {
    current_password: currentPassword,
    new_password: newPassword,
  });
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
  /**
   * True when the sweep could not read part (or all) of the grid. The counters
   * cannot express this on their own: a sweep that read NOTHING and a sweep that
   * FOUND nothing both land total=0, hunted=0, failed=0 — so an outage rendered
   * as a fully-drained queue for the whole blind window. Key off this, never off
   * `total === 0`.
   */
  degraded?: boolean;
  /** Which queries failed ("severity critical", "rule ET SCAN thing"). */
  grid_errors?: string[];
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

export interface BackupArchive {
  name: string;
  size_bytes: number;
  modified: string;
}

export interface Maintenance {
  backups: BackupArchive[];
  backups_dir: string;
  blocklists_dir: string;
  blocklists_refreshed: string | null;
  blocklist_files: number;
}

/** Observed maintenance facts (backup archives, blocklist freshness) — admin. */
export function getMaintenance(): Promise<Maintenance> {
  return request<Maintenance>('/maintenance');
}

export interface QualityEvalStatus {
  running: boolean;
  last_run: string | null;
  last_exit_code: number | null;
  last_detail: string;
  note?: string | null;
}

/** Start the quality micro-eval now (single-flight, background) — admin. */
export function startQualityEval(): Promise<QualityEvalStatus> {
  return post<QualityEvalStatus>('/quality/eval/run');
}

/** Poll the quality-eval run state — admin. */
export function getQualityEvalStatus(): Promise<QualityEvalStatus> {
  return request<QualityEvalStatus>('/quality/eval/status');
}

/**
 * Count of pending detection-tuning mute recommendations (admin-gated).
 * Feeds the Dashboard nudge; callers treat a 403/error as "hide the nudge".
 */
export function getDetectionTuningSummary(): Promise<{ pending: number }> {
  return request<{ pending: number }>('/detection-tuning/summary');
}

/** Launch a background discovery scan; returns the (running) status. */
export function startDiscoveryScan(): Promise<DiscoveryScanStatus> {
  return post<DiscoveryScanStatus>('/discovery/scan');
}

/** Poll the discovery scan status. */
export function getDiscoveryScan(): Promise<DiscoveryScanStatus> {
  return request<DiscoveryScanStatus>('/discovery/scan');
}

// ── Host dossier ──────────────────────────────────────────────────────────────
// The dossier keeps two physically separate lanes per field — what the network
// sweep inferred and what an operator declared — and stores no "current value"
// at all; every response here is the resolver's read-time answer.
//
// The four mutating helpers are ADMIN-gated server-side and each answers with
// the WHOLE re-resolved dossier. Callers must re-render from that response
// rather than patching the field they touched: setting `role` can clear a
// conflict, and a partial update would leave a disagreement on screen that no
// longer exists.

export interface DossierQuery {
  /** Substring match over the host key and its resolved identity fields. */
  q?: string;
  /** Coarse prefilter over the stored lanes. The resolver still applies the
   *  confidence floor and staleness window, so a host listed under a role can
   *  resolve to unknown on its own page — the honest answer, not a mismatch. */
  role?: string;
  /** Hosts carrying an operator declaration, or hosts running on pure inference. */
  source?: DossierLane;
  /** `broken`: hosts with no clean build on record — never built, or the last
   *  build errored. The same predicate `DossierSummary.never_built` counts, so
   *  the count and the filtered view describe one set. */
  health?: DossierHealthFilter;
  limit?: number;
  offset?: number;
  sort?: DossierSortKey;
}

/** A page of the network, every field resolved. Paged in SQL: `total` is the
 *  whole match set, not the length of the page. */
export function listDossiers(query: DossierQuery = {}): Promise<DossierList> {
  const p = new URLSearchParams();
  if (query.q) p.set('q', query.q);
  if (query.role) p.set('role', query.role);
  if (query.source) p.set('source', query.source);
  if (query.health) p.set('health', query.health);
  // `!= null` rather than truthiness: offset 0 is a real page (the first one),
  // and dropping it as falsy is how a pager that pages forward can never page
  // back to the top.
  if (query.limit != null) p.set('limit', String(query.limit));
  if (query.offset != null) p.set('offset', String(query.offset));
  if (query.sort) p.set('sort', query.sort);
  const qs = p.toString();
  return request<DossierList>('/dossiers' + (qs ? `?${qs}` : ''));
}

/**
 * Open disagreements the builder has kept seeing, oldest first. A row stays here
 * after it has prodded — the interval throttles the NOTIFICATION, not the
 * disagreement — and snoozed rows are excluded, which is what "keep mine" bought.
 */
export function getDossierConflicts(limit?: number): Promise<DossierConflicts> {
  return request<DossierConflicts>(
    '/dossiers/conflicts' + (limit != null ? `?limit=${limit}` : ''),
  );
}

/**
 * Network-wide dossier counts, for the host list's KPI strip.
 *
 * A separate request from `listDossiers` on purpose. That one is a SQL page of
 * up to 5,000 hosts; these numbers are aggregates over the whole table, and
 * deriving any of them from a page would state a figure about fifty rows as if
 * it described the network. It carries its own freshness (`last_built_at`,
 * `schedule_enabled`) because the sweep schedule is off by default.
 */
export function getDossierSummary(): Promise<DossierSummary> {
  return request<DossierSummary>('/dossiers/summary');
}

/**
 * One host's dossier: every field resolved, both lanes, all evidence.
 * An address the sweep has never seen answers 200 with `found: false` and twelve
 * `no_signal` fields — render that as "no dossier for this host", because it is
 * a real answer and an error state there would read as "nothing notable". Only a
 * path segment that is not an address at all is a 404.
 */
export function getDossier(ip: string): Promise<Dossier> {
  return request<Dossier>(`/dossiers/${encodeURIComponent(ip)}`);
}

export interface DossierOverrideInput {
  field: DossierFieldName;
  /** The scalar declaration. Blank/whitespace is refused server-side (400
   *  `empty_override`) — omit it entirely when declaring a structured field
   *  rather than sending an empty string beside `value_json`. */
  value?: string;
  /** The structured declaration, for services_offered / activity_profile /
   *  management_plane — the three fields a scalar cannot carry. */
  value_json?: unknown;
  note?: string;
}

/**
 * Declare a field's value — admin. Not a hint the next build can outvote: it
 * lands in a separate column family the resolver reads first, so no inference
 * run can clobber it. The builder keeps observing underneath, which is how a
 * persistent disagreement accumulates into one rate-limited "reconsider?" prod.
 */
/** What a bulk declaration did, host by host — a three-way partition. */
export interface DossierBulkOverrideResult {
  /** Took the declaration. */
  updated: string[];
  /** The sweep has never built a row for these. */
  not_found: string[];
  /** Hit an error of their own; the rest of the batch still went through. */
  failed: Array<{ ip: string; reason: string }>;
}

/**
 * Declare one field across a selection of hosts — admin.
 *
 * The server reuses the SAME store path as the single-host declare, host by
 * host, so the operator lane keeps exactly one writer and a bulk tag cannot
 * drift from a single one. Returns a partition rather than a count: a selection
 * can outlive a sweep, and "3 of 5" with no names leaves the operator
 * re-checking all five.
 */
export function bulkSetDossierOverride(
  ips: string[],
  body: DossierOverrideInput,
): Promise<DossierBulkOverrideResult> {
  return post<DossierBulkOverrideResult>('/dossiers/bulk-override', { ips, ...body });
}

export function setDossierOverride(ip: string, body: DossierOverrideInput): Promise<Dossier> {
  return post<Dossier>(`/dossiers/${encodeURIComponent(ip)}/override`, body);
}

/**
 * Accept the inference: drop the operator value and close the disagreement —
 * admin. Throws 409 (`no_operator_override`) on a field carrying no override;
 * an inferred value cannot be deleted, the next build writes it straight back.
 */
export function clearDossierOverride(ip: string, field: DossierFieldName): Promise<Dossier> {
  return del<Dossier>(`/dossiers/${encodeURIComponent(ip)}/override/${encodeURIComponent(field)}`);
}

/**
 * "Keep mine": postpone this disagreement, with an interval that doubles per
 * prod already fired and caps at 90 days — admin. Nothing is resolved; the
 * override stands and the builder keeps observing, so the conflict re-surfaces
 * later unless the evidence comes back into agreement. Throws 409
 * (`no_open_conflict`) when nothing currently disagrees with the override.
 */
export function snoozeDossierConflict(ip: string, field: DossierFieldName): Promise<Dossier> {
  return post<Dossier>(
    `/dossiers/${encodeURIComponent(ip)}/conflicts/${encodeURIComponent(field)}/snooze`,
  );
}

/**
 * Rebuild the network dossier now, in the background — admin, single-flight.
 * A second start while a sweep is in flight reports the running one instead of
 * launching a second (a sweep is hundreds of hosts x several grid round trips,
 * and two at once is the connection-pool pressure that has frozen this app
 * before). `note` reads 'dossier disabled' when the master switch is off.
 */
export function startDossierRefresh(): Promise<DossierRefreshStatus> {
  return post<DossierRefreshStatus>('/dossiers/refresh');
}

/** Poll the network sweep — admin. */
export function getDossierRefreshStatus(): Promise<DossierRefreshStatus> {
  return request<DossierRefreshStatus>('/dossiers/refresh');
}

/**
 * One host's LIVE activity: peers, connection volume, users, alert count.
 *
 * Deliberately a second call rather than more fields on `getDossier`. The
 * dossier is swept and cached and answers while Security Onion is down; this
 * reads the grid on every request and cannot. Fetching them separately is what
 * lets the host page keep its identity half on screen and degrade only this one
 * when the grid is unreachable (503 `grid_unavailable`).
 *
 * `range` is always sent even though the server defaults to 24h: the volume
 * histogram's bucket width is derived from it, so the request and the chart must
 * name the same window.
 */
export function getHostActivity(
  ip: string,
  range: HostActivityRange = '24h',
): Promise<HostActivity> {
  return request<HostActivity>(
    `/dossiers/${encodeURIComponent(ip)}/activity?range=${encodeURIComponent(range)}`,
  );
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
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
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

// ── Saved list views (per user, server-held) ────────────────────────────────
//
// These three opt out of the global 401 handoff, because here a 401 is an
// ANSWER, not an expiry: a saved view belongs to a person, and a deployment
// running with API_AUTH_REQUIRED=false has nobody to own one. That is the
// steady state of the demo and of every hermetic instance, so the redirect sent
// Alerts, Investigations, Hunts and Hosts — the four screens that fetch views on
// mount — to a login page nobody could sign in to, while Notifications (which
// fetches none) stayed usable. Refused now surfaces as an ApiError carrying
// {status, reason}; useSavedViews reads it and simply drops the controls.

/** This user's saved views, oldest first — optionally for one screen. */
export function listSavedViews(screen?: SavedViewScreen): Promise<SavedView[]> {
  const qs = screen ? `?screen=${encodeURIComponent(screen)}` : '';
  return request<{ rows: SavedView[] }>(`/me/views${qs}`, { skipLoginRedirect: true }).then(
    (r) => r.rows,
  );
}

/** Save the current filter set under a name. Re-saving a name replaces it. */
export function saveView(
  screen: SavedViewScreen,
  name: string,
  query: SavedViewQuery,
): Promise<SavedView> {
  return post<SavedView>('/me/views', { screen, name, query }, { skipLoginRedirect: true });
}

export function deleteSavedView(id: number): Promise<{ ok: boolean }> {
  return del<{ ok: boolean }>(`/me/views/${id}`, { skipLoginRedirect: true });
}
