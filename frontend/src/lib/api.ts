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
  AlertsEmptyReason,
  AuditChainVerifyResult,
  Backtest,
  ChatMessage,
  Config,
  ConnTestResult,
  DangerSetting,
  Dossier,
  DossierActivityFilter,
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
  HuntKind,
  HuntRehuntResult,
  HuntRow,
  HuntStat,
  Investigation,
  InvestigationList,
  InvestigationRow,
  Me,
  Notification,
  PreflightDetail,
  PreflightSummary,
  RehuntResult,
  RepresentativeOut,
  SavedView,
  SavedViewQuery,
  SavedViewScreen,
  SigmaDraft,
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
      throw new Error('The request timed out. The soc-ai API is slow or down, or Security Onion behind it is.');
    }
    throw new Error('Network error. Check that the soc-ai API is reachable.');
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
      const hint =
        body?.detail?.hint ??
        body?.detail?.message ??
        (typeof body?.detail === 'string' ? body.detail : null);
      if (hint) detail = hint;
      // The house error shape is {reason, hint}: `hint` is the sentence shown to
      // the analyst, `reason` the machine-readable code. Dropping `reason` forced
      // callers to regex the prose to work out WHAT failed — which breaks the
      // moment the wording is edited, and can't separate two rejections that read
      // alike. Carry it on the Error instead.
      //
      // `?? body?.detail?.message`: one endpoint (GET /config/audit/verify-chain)
      // uses {reason, message} instead of {reason, hint} — deliberately, per its
      // own pinned test (tests/test_degraded_grid_panels.py) — so its partial-read
      // shard narrative was being flattened to the generic "502 Bad Gateway" one
      // layer from the screen. `??` only falls through when `hint` is absent, so
      // every existing {reason, hint} caller is unaffected.
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

/** GET /alerts — the grouped queue, plus whether the rows are the whole queue.
 *
 *  An envelope rather than a bare array because the grid caps every terms
 *  aggregation, and this screen renders "N detections · M events in window"
 *  from the rows it gets. Past the cap both are floors, and a floor rendered
 *  as a total makes the queue look smaller and calmer than it is. A bare array
 *  has nowhere to carry a fact about the array. */
export interface AlertQueue {
  groups: AlertGroup[];
  /** The grid could not return every distinct group, or the merge of its two
   *  source aggregations had to be re-cut. Set by whichever cut fired, never
   *  inferred from `groups.length` against a copied cap: an exactly-full page
   *  is not a cut one, and muting removes rows AFTER the cap is applied. */
  truncated: boolean;
  /** Documents in groups the grid never returned, from the aggregation's own
   *  `sum_other_doc_count`. Zero alongside `truncated` is a real state — the
   *  merge re-cut drops rows that WERE returned, and their documents are
   *  already inside the queue's totals. */
  other_docs: number;
}

export function getAlerts(query: AlertQuery = {}): Promise<AlertQueue> {
  const qs = alertQueryParams(query);
  return request<AlertQueue>('/alerts' + (qs ? `?${qs}` : ''));
}

/**
 * Why the queue is empty. Call this ONLY when getAlerts came back with
 * nothing. It costs four counts against the grid, and the answer is only
 * meaningful for an empty screen.
 *
 * Deliberately sends the WINDOW alone, not the analyst's severity/OQL/hide-acked
 * narrowing. The backend answers about the configured alerts filter, and its
 * verdicts compose with any narrowing the analyst added: `not_empty` means the
 * filter did match events in this window, so an empty screen is the analyst's
 * own view and the bare sentence is the right thing to say.
 */
export function getAlertsEmptyReason(query: AlertQuery = {}): Promise<AlertsEmptyReason> {
  const qs = alertQueryParams({ range: query.range, from: query.from, to: query.to });
  return request<AlertsEmptyReason>('/alerts/empty-reason' + (qs ? `?${qs}` : ''));
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
 * (fallback-marked runs, and runs that died reaching no verdict); `status`
 * accepts the display statuses. Both are
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
  /** Which half of a pipeline-error set: 'live' (still needs a retry) or
   *  'handled' (dismissed, or superseded by a later run that landed a verdict).
   *  Omitted means the whole set. The Dashboard tile and the list it deep-links
   *  to send the same value, which is what stops the two disagreeing. */
  errorState?: string;
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
  if (q.errorState) p.set('error_state', q.errorState);
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
  if (!res.ok) throw new Error(`Export failed: ${res.status}`);
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
  /** Sent only when set. The Hunts screen filters kind client-side over the
   *  fetched page today; this is the seam for the server to take it over. */
  kind?: HuntKind;
}

export function getHunts(query: HuntsQuery = {}): Promise<HuntRow[]> {
  const p = new URLSearchParams();
  if (query.since) p.set('since', query.since);
  if (query.until) p.set('until', query.until);
  if (query.kind) p.set('kind', query.kind);
  const qs = p.toString();
  return request<HuntRow[]>('/hunts' + (qs ? `?${qs}` : ''));
}

export function getHuntStats(): Promise<HuntStat[]> {
  return request<HuntStat[]>('/hunts/stats');
}

export function getHunt(id: string): Promise<HuntDetailData> {
  return request<HuntDetailData>(`/hunts/${encodeURIComponent(id)}`);
}

/** Promote one hunt finding into a full investigation of its cited evidence.
 * Idempotent server-side: a running/complete promotion returns its id. */
export function promoteFinding(
  huntId: string,
  ordinal: number,
): Promise<{ investigation_id: string; existing?: boolean }> {
  return post(`/hunts/${encodeURIComponent(huntId)}/findings/${ordinal}/investigate`);
}

/**
 * Client budget for the two draft-detection calls below. A draft is ONE
 * synchronous heavy-model call — 16–44s measured live — so the default 20s
 * request budget guaranteed "Request timed out" while the server finished
 * (and then discarded) a perfectly good draft. Sits ABOVE the server's own
 * 150s draft budget (`sigma_draft_timeout_s`), so a slow draft gets the
 * server's honest 504 before the client aborts; the review pane's spinner
 * covers the wait. Drafts are deliberately stateless in v1 — no enqueue/poll
 * — so a bounded synchronous call is the whole contract.
 */
const DRAFT_DETECTION_TIMEOUT_MS = 180_000;

/**
 * Draft a Sigma detection rule (+ its would-have-fired dry run) from one hunt
 * finding, by ordinal (1.3 slice 3, export-only — no Security Onion write).
 * 403 `sigma_authoring_disabled` when `sigma_authoring_enabled` is off; the
 * caller gates the button on that same flag (see `AboutInfo`) so this is a
 * backstop, not the primary guard.
 */
export function draftFindingDetection(huntId: string, ordinal: number): Promise<SigmaDraft> {
  return post(`/hunts/${encodeURIComponent(huntId)}/findings/${ordinal}/draft-detection`, undefined, {
    timeoutMs: DRAFT_DETECTION_TIMEOUT_MS,
  });
}

/**
 * Draft a Sigma detection rule from a complete, hunt-kind investigation's
 * promoted finding — same pipeline as `draftFindingDetection`, addressed by
 * investigation id instead of hunt id + ordinal.
 */
export function draftInvestigationDetection(invId: string): Promise<SigmaDraft> {
  return post(`/investigations/${encodeURIComponent(invId)}/draft-detection`, undefined, {
    timeoutMs: DRAFT_DETECTION_TIMEOUT_MS,
  });
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
  templateId?: number,
): Promise<{ hunt_id: string }> {
  return post<{ hunt_id: string }>('/hunts/chat', {
    objective,
    prior_hunt_id: priorHuntId ?? null,
    // The starter the objective came from. The server reads it for the
    // analytics that starter names, and renders them into the objective.
    template_id: templateId ?? null,
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
  /** WHAT WAS RUNNING when the point was measured (migration 0040) — the app
   * version, the build inside it, and the analyst route the batch ran against.
   * Without these a bend in the trend is weather; with them it can be pinned to
   * a change. `code_commit` is stamped into the image at build time and is null
   * on any build nothing stamped; all three are null on pre-0040 rows.
   *
   * OPTIONAL, not merely nullable, for the same reason as `alarm_codes` above:
   * a server older than this release omits them from the JSON entirely. */
  app_version?: string | null;
  code_commit?: string | null;
  analyst_model?: string | null;
}

/** When the trend last moved, and what the last attempt did. A nightly that
 * finds no eligible alerts writes no point, so the points alone cannot say
 * whether it ran. Every field here is durable: the first three come from the
 * trend table and the live settings, the `last_attempt_*` three from
 * `quality_eval_attempts`, which records every finished attempt including the
 * ones that write no point. They used to be the server process's memory of its
 * run-now/scheduler slot and went null on every restart, so a reader could not
 * tell "never attempted" from "attempted, and forgotten". */
export interface QualityFreshness {
  /** The newest point's timestamp, or null with no points. */
  latest_ts: string | null;
  /** The in-app nightly is enabled. */
  scheduled: boolean;
  /** `scheduled`, and the newest point is older than two scheduled runs. */
  stale: boolean;
  /** When the last attempt finished. Null means no attempt has ever been
   *  recorded on this deployment — not merely none since the last restart. */
  last_attempt_at: string | null;
  /** That attempt's exit code: 0 wrote a point, 2 found no eligible alerts,
   *  5 failed. */
  last_exit_code: number | null;
  /** The run's own one-line reason (the exit-2 "no eligible alerts" text). */
  last_detail: string | null;
}

export interface QualityTrend {
  /** Oldest → newest (server-ordered), ready to plot left-to-right. */
  points: QualityPoint[];
  freshness: QualityFreshness;
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
  if (!res.ok) throw new Error(`Preview failed: ${res.status} ${res.statusText}`);
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
  requiredDatasets: string[]; // one requirement per element; "a|b" means either plane satisfies it
  defaultWindowMinutes: number;
  builtin: boolean; // shipped (code-owned) vs operator-saved custom
  createdBy: string;
  createdAt: string;
  available: boolean; // false iff any requiredDataset is absent from the grid
  missingDatasets: string[]; // exactly which telemetry the grid lacks (for the flag)
  // Requirements met only by imported documents — present on the grid, and no
  // sensor here is producing them. The template is still available; the hunt
  // reads history. Optional: an older server does not send it.
  backfillOnlyDatasets?: string[];
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
  // The catalog analytics this starter runs BEFORE the investigation, in the
  // order it runs them. The server renders them into the objective. Optional:
  // a server predating the field does not send it.
  analytics?: string[];
}

/** Create payload for a custom template (always saved builtin=false). */
export interface HuntTemplateInput {
  name: string;
  objective_template: string;
  required_datasets: string[];
  analytics?: string[];
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

/** One declarative hunt-catalog spec joined to its sweep trail
 *  (GET /hunt-catalog, `HuntCatalogSpecOut`). The `last_*` stamps read the
 *  trail's whole retention and are null only when it has nothing — a
 *  never-swept spec has null timestamps, `blind: false` and zero counts, and
 *  `last_swept_at === null` is the one fact that says its eyesight is
 *  untested. `blind` is the NEWEST sweep's verdict: the precondition matched
 *  nothing, so the telemetry the spec reads is absent, not clean. The `*_24h`
 *  fields are a rate. Timestamps end in `Z`, not `+00:00`. */
export interface PriorCoverage {
  last_run_at: string | null;
  measured: number;
  learning: number;
  blind: number;
  not_applicable: number;
  fired: number;
  shadow: boolean;
}

export interface HuntCatalogSpec {
  id: string;
  title: string;
  /** informational | low | medium | high | critical — kept as a string so a
   *  level a newer backend adds renders (as info) rather than throws. */
  level: string;
  scope_kind: string;
  attack: string[];
  /** Which loop runs this spec. `match` is swept by the catalog sweep and
   *  every `last_*`/`*_24h` field below describes that sweep. `profile` is
   *  answered from stored behavioural baselines by `soc-ai priors` and is NOT
   *  swept here, so those fields describe a loop that no longer runs it. */
  evaluator: string;
  /** The prior sweep's newest verdict for a `profile` spec: (spec, entity)
   *  evaluations by coverage state. Null for a `match` spec, and for a profile
   *  spec that has never been run. `measured` is the only state a departure
   *  can be scored in -- a spec whose measured is 0 was not scored against a
   *  single entity, and that is not evidence of a clean network. */
  coverage: PriorCoverage | null;
  last_swept_at: string | null;
  last_fired_at: string | null;
  blind: boolean;
  last_error: string | null;
  sweeps_24h: number;
  fired_24h: number;
  fresh_24h: number;
  already_handled_24h: number;
  /** How many of the window's sweeps were `spec-sweep --shadow` runs. A
   *  shadow sweep counts what it would have surfaced toward `fresh_24h` and
   *  never toward `fired_24h`, so this is what lets a row explain "fresh 2,
   *  fired 0" as the shadow reporting rather than a spec withholding. */
  shadow_24h: number;
  /** Documents the NEWEST sweep could not decide, because an exclusion reads
   *  a field they do not carry: neither matched nor ruled out, so the run is
   *  not clean. The newest sweep's fact, not a 24h rate, so it clears when the
   *  condition does. Nothing else on the row can carry it — a run that
   *  discarded everything matched nothing and bucketed nothing, so every
   *  counter reads zero, exactly like a healthy quiet spec. */
  undecided_docs: number;
  /** Documents the NEWEST sweep matched and could not group into any scope
   *  bucket. They are inside the sweep's matched count and inside no
   *  candidate, and the gate then drops the candidates that did surface, so
   *  the row reads fired 0 · fresh 0 over documents the detection hit. */
  unattributed_docs: number;
  /** Documents in scopes the grid never returned to the NEWEST sweep, because
   *  its bucket ceiling was hit — read from the terms aggregation's own
   *  `sum_other_doc_count`, never inferred. The one counter here where the
   *  row is not zeros: `fired`/`fresh` are real numbers that are too small,
   *  and an under-report is indistinguishable from a full count. */
  truncated_docs: number;
  /** Which tier the analytic comes from: `shipped` is a file in the
   *  repository, `local` is a row. Optional so a response from an older
   *  backend still parses. */
  tier?: string;
  /** Whether the analytic runs, and how: candidate, shadow, live or retired.
   *  A retired analytic stays in the list with its ledger and its reason, so
   *  the row has to say that it no longer runs. */
  status?: string;
}

/** GET /hunt-catalog — every spec in catalog order plus the sweep loop's
 *  live settings, which ride along because four rows of zeros mean one thing
 *  with the loop on and another with it off. `last_sweep_at` is the newest
 *  row across the whole trail, catalog membership aside. */
export interface HuntCatalog {
  specs: HuntCatalogSpec[];
  sweeps_enabled: boolean;
  /** The interval and window a sweep actually runs with, after the backend's
   *  floor (interval, 5m) and clamp (window widened past the interval), not
   *  the settings as typed. The trail rows record the clamped window, so
   *  "looks back 61m" here matches them when Config says 60. */
  sweep_interval_minutes: number;
  sweep_window_minutes: number;
  last_sweep_at: string | null;
}

/** The hunt catalog with each spec's sweep status (analyst-readable). */
export function getHuntCatalog(): Promise<HuntCatalog> {
  return request<HuntCatalog>('/hunt-catalog');
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
  /** Which failure, when `ok` is false: 'partial' | 'overloaded' | 'timeout' |
   *  'refused'. Absent means the probe did not classify it. */
  kind?: string;
}
export interface Health {
  es: HealthComponent;
  llm: HealthComponent;
  /** The Security Onion web API: the path every acknowledge, escalate and case
   *  write travels. Optional in the TYPE only, so a page served by an older
   *  build degrades to "not reported" instead of throwing on `.ok`. */
  so?: HealthComponent | null;
  pcap?: HealthComponent | null;
}

/** Live upstream status (ES / model gateway / Security Onion API / PCAP) for
 *  the header indicator. */
export function getHealth(): Promise<Health> {
  return request<Health>('/health');
}

/** Closed setup-health projection (any authenticated caller) — Wave 1's
 *  doctor checks minus the fitness probe, server-cached at a 600s TTL. Feeds
 *  the Dashboard's persistent setup-health card. */
export function getPreflight(): Promise<PreflightSummary> {
  return request<PreflightSummary>('/health/preflight');
}

/** Per-check rows + hints behind the summary above — admin-only
 *  (require_admin_api). Read from cache; use `refreshPreflight` to force a
 *  fresh run. */
export function getPreflightDetail(): Promise<PreflightDetail> {
  return request<PreflightDetail>('/health/preflight/detail');
}

/** Force a fresh doctor run past the server cache and re-cache the result
 *  server-side, so the very next `getPreflight` poll reads correctly.
 *  Admin-only. Returns the same shape as `getPreflightDetail` (the refreshed
 *  detail) — but its only caller (the Dashboard's Re-check) doesn't rely on
 *  that return value; it always refetches both `getPreflight` and
 *  `getPreflightDetail` afterward regardless, since a partial fix can leave
 *  the summary's `degraded` boolean unchanged while the failing check itself
 *  changes, and only an explicit refetch moves the detail rows off a
 *  now-stale one. */
export function refreshPreflight(): Promise<PreflightDetail> {
  return request<PreflightDetail>('/health/preflight/detail?refresh=true');
}

// Resolve-once caches for the two per-mount probes (F19, dogfood 1.3). Every
// detail screen re-fetched /about on mount just to gate a default-off flag,
// and most re-fetched /me for a username — both answers are stable for a whole
// session. Cache the PROMISE (so concurrent mounts share one in-flight fetch),
// and invalidate on the events that can actually change the answer: a config
// apply for /about (its feature flags are hot-appliable), a session or status
// change for /me. A REJECTED probe is never cached — fail-closed callers hide
// the feature for that mount, and the next mount deserves a fresh attempt
// rather than a remembered failure.
let aboutPromise: Promise<AboutInfo> | null = null;
let mePromise: Promise<Me> | null = null;

/** Drop the cached `/about` + `/me` answers so the next call re-fetches.
 *  Called after a config apply (a hot flag flip must be honored) and on
 *  session changes (login/logout/status). Exported for tests. */
export function invalidateSessionProbes(): void {
  aboutPromise = null;
  mePromise = null;
}

/** Build metadata (version, repo, license) plus the feature flags a screen needs
 *  before it renders — see `AboutInfo`, which is the whole contract. Cached for
 *  the session; a config apply invalidates it (see `invalidateSessionProbes`). */
export function getAbout(): Promise<AboutInfo> {
  if (aboutPromise === null) {
    const p: Promise<AboutInfo> = request<AboutInfo>('/about').catch((e: unknown) => {
      // Clear only our own entry — an invalidation while this was in flight
      // may already have installed a fresh probe we must not discard.
      if (aboutPromise === p) aboutPromise = null;
      throw e;
    });
    aboutPromise = p;
  }
  return aboutPromise;
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
  return post<{ ok: boolean; restart_required: boolean }>('/config/setting', { key, value }).then(
    (r) => {
      // A config apply can flip the feature flags the cached /about carries
      // (hot-apply), so the cache must not outlive it.
      invalidateSessionProbes();
      return r;
    },
  );
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
  return post<{ ok: boolean }>(`/config/users/${id}/set-role`, { role }).then((r) => {
    invalidateSessionProbes(); // an admin editing their OWN row changes /me
    return r;
  });
}

/** Return the currently-logged-in user's username, role, and status. Cached for
 *  the session (see `invalidateSessionProbes`); login/logout/status changes
 *  invalidate it. */
export function getMe(): Promise<Me> {
  if (mePromise === null) {
    const p: Promise<Me> = request<Me>('/me').catch((e: unknown) => {
      if (mePromise === p) mePromise = null;
      throw e;
    });
    mePromise = p;
  }
  return mePromise;
}

/** Update the current user's status string (trim + cap enforced server-side). */
export function setMyStatus(status: string): Promise<{ ok: boolean; status: string }> {
  return post<{ ok: boolean; status: string }>('/me/status', { status }).then((r) => {
    invalidateSessionProbes(); // the cached /me carries the old status
    return r;
  });
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
  }).then((r) => {
    invalidateSessionProbes(); // same config-apply rule as setSetting
    return r;
  });
}

export function testConnection(target: 'es' | 'llm'): Promise<ConnTestResult> {
  return post<ConnTestResult>(`/config/danger/test/${target}`);
}

/** Re-run the tamper-evident audit hash chain check against the live ES audit
 * index (soc_ai.audit.verify.verify_audit_chain) — the Diagnostics panel's
 * "Verify audit chain" control. Admin-only server-side. NOT fail-soft: an
 * unreachable or partially-read index rejects this promise rather than
 * resolving with a result (see AuditChainVerifyResult's doc) — a caller must
 * not fold that rejection into "tampered". */
export function verifyAuditChain(): Promise<AuditChainVerifyResult> {
  return request<AuditChainVerifyResult>('/config/audit/verify-chain');
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

/** Return every severity at or above `floor`, plus the alerts that carry no
 *  severity label (e.g. "high" → ["critical","high","unknown"]).
 *
 *  'unknown' rides along at every floor for the reason the backend's
 *  config_severity_band does: a floor is a comparison, and an alert whose
 *  document has no `event.severity_label` has nothing to compare. Leaving it
 *  out is how a bulk sweep over a queue of 40 endpoint and honeypot alerts
 *  came back with zero targets. */
export function severitiesAtOrAbove(floor: string): string[] {
  const i = _SEV_LADDER.indexOf(floor as typeof _SEV_LADDER[number]);
  const band = i < 0 ? ['critical', 'high'] : Array.from(_SEV_LADDER.slice(0, i + 1));
  return [...band, 'unknown'];
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
  /** Skipped because Security Onion already records them acknowledged. Non-zero
   *  only on an index that cannot hide an acknowledged alert from a query, where
   *  the group keeps showing events the grid has already been told about. */
  already_acked?: number;
  /** Events in the group this press did not write. `> 0` means another press
   *  has something left to do. */
  remaining?: number;
}

export interface EscalateGroupResult {
  escalated: number;
  failed: number;
  total: number;
  capped: boolean;
  /** Alerts a case was withheld from because one already exists. soc-ai's own
   *  escalation ledger, Security Onion's case links, or the alert's
   *  `event.escalated` flag says so. Each one is a duplicate case not opened,
   *  and nothing else belongs in this count. */
  already_escalated?: number;
  /** Alerts skipped because Security Onion already acknowledged them. A
   *  dismissal, not a case. */
  already_acked?: number;
  /** Alerts an earlier escalate claimed and never came back from, whose outcome
   *  the grid could not confirm either way. Not escalated, and not safe to
   *  escalate. */
  unresolved?: number;
  /** Cases Security Onion created and then attached nothing to, which happens
   *  when the alert is no longer on the grid. Each is counted in `failed` and
   *  not in `escalated`, because the alert is on no case, and each is an empty
   *  case now sitting in the queue for the operator to close or reuse. */
  empty_cases?: string[];
  remaining?: number;
}

/** One escalate the ledger claimed and never got an answer for. The claim is
 *  written before the case is opened, so the row is normal for a moment and a
 *  standing fact only when it outlives the settling window. */
export interface StrandedClaim {
  alert_id: string;
  /** The account that pressed escalate: a username, `token:<name>`, or
   *  "anonymous". */
  escalated_by: string;
  /** When the claim was taken, ISO-8601 with a Z. The AGE is the fact: four
   *  minutes is a request in flight, four days is an alert nobody can
   *  escalate. */
  claimed_at: string;
}

/** GET /escalations/stranded — what the escalation ledger is holding that
 *  nothing will settle on its own. Reads soc-ai's own table and never the
 *  grid, so it answers on the deployment that accumulates these: one whose
 *  case index cannot be read, and whose claims therefore never reconcile. */
export interface StrandedClaims {
  claims: StrandedClaim[];
  /** A count over the whole set, NOT `claims.length` — the list is capped, and
   *  a panel that showed its rows and called that the total would under-report
   *  in exactly the way this surface exists to stop. */
  total: number;
  /** How old a claim has to be before it counts as stranded. Zero claims mean
   *  different things with different windows, and the ledger is claim-first,
   *  so without this "nothing stranded" could just mean "looked too soon". */
  settling_minutes: number;
}

/** Escalate claims that never came back with a case id (analyst-readable). */
export function getStrandedEscalations(): Promise<StrandedClaims> {
  return request<StrandedClaims>('/escalations/stranded');
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
  /** `active`: hosts with observed events (`event_count > 0`) — the Hosts
   *  screen's default. Hides the DNS-only census entries that land with
   *  `event_count=0` and otherwise drown the list. */
  activity?: DossierActivityFilter;
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
  if (query.activity) p.set('activity', query.activity);
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
    throw new Error('Network error. Check that the soc-ai API is reachable.');
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
  // A different person may now be signed in — the cached /me (and /about,
  // whose flag view is cheap to re-probe) must not carry over.
  invalidateSessionProbes();
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
  } finally {
    invalidateSessionProbes();
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

// ── Leads (hunting release, phase 2) ─────────────────────────────────────────

export interface LeadObservation {
  kind: string;
  summary: string | null;
  occurrences: number;
  born_at: string | null;
  first_seen_at: string | null;
  /** Which source wrote it: profile, catalog, alert, hunt or candidate. */
  source: string;
  /** True when the analytic that wrote it is not live. */
  shadow: boolean;
  /** The label the server wrote for this kind. The server knows the analytic
   *  that wrote the row, so its label wins over the table in lib/kinds.ts.
   *  Absent on a route that sends none. */
  kind_label?: string | null;
}

export interface Lead {
  id: number;
  status: string;
  formed_at: string | null;
  updated_at: string | null;
  entities: string[][];
  kinds: string[];
  /** One label per entry in `kinds`, in the same order. Absent on a route that
   *  sends none, and the table in lib/kinds.ts answers instead. */
  kind_labels?: string[];
  weight_at_formation: number;
  scope_count: number;
  hunt_id: string | null;
  /** Recorded in shadow: never surfaced as an action. Shown WITH the flag,
   *  because the whole point of the shadow week is to read them. */
  shadow: boolean;
  /** True when one kind formed the lead by itself, by repeating until its
   *  weight reached 1.0. */
  single_signal: boolean;
  observations: LeadObservation[];
  dismissed_reason?: string | null;
  dismissed_at?: string | null;
  /** The investigation a promoted lead became. Absent on a route that sends
   *  none, and the strip then names the promotion without a link. */
  investigation_id?: string | null;
  /** Whether that investigation is still in the store. A lead kept the id of a
   *  row that had gone, so the link promised a page and landed on "No such
   *  investigation". Absent on a route that sends none, and the surface then
   *  keeps the link it has always shown. */
  investigation_exists?: boolean;
  /** The status of the hunt attached to this lead. A finished hunt is what
   *  turns the lead from Hunting into Hunted. */
  hunt_status?: 'running' | 'complete' | 'error' | 'interrupted' | 'cancelled' | null;
  /** The outcome label of that hunt, in the backend's own words. One example
   *  is "No threat observed \u00b7 visibility gap". */
  hunt_outcome_label?: string | null;
  /** Auto-hunt is on and the loop has not started this lead's hunt yet. The
   *  lead waits on the loop and not on the analyst, so the pill says so.
   *  Absent on a route that sends none, and the lead then reads as New. */
  hunt_queued?: boolean;
  /** Open leads from the last 7 days that share an analytic, an external
   *  address or a technique with this one. Absent on a route that sends none,
   *  and the row then carries no related chip. */
  related_count?: number;
}

/** One open lead that relates to the lead on screen. Computed on read, so the
 *  row carries the reason it was joined rather than a stored edge. */
export interface RelatedLead {
  lead_id: number;
  entities: [string, string][];
  /** What the two leads share, in the server's words. */
  reason: string;
  formed_at: string | null;
  /** The lead status, for the pill. The related lead is open by definition,
   *  and the pill reads the word the strip reads. */
  status: string;
  /** The status of the hunt on the related lead. The stored status alone
   *  cannot tell a running hunt from a finished one, so the panel read
   *  "In progress" over a lead every other surface read as Hunted. Absent on
   *  a route that sends none. */
  hunt_status?: 'running' | 'complete' | 'error' | 'interrupted' | 'cancelled' | null;
  /** The outcome label of that hunt, in the backend's own words. */
  hunt_outcome_label?: string | null;
}

/** One observation on the lead detail page, with its live weight. */
export interface LeadObservationDetail extends LeadObservation {
  id: number;
  spec_id: string;
  /** Whether `spec_id` names an analytic this deployment holds. An alert
   *  verdict writes an observation and an alert has no analytic, so the id was
   *  a link to a drawer that could not be read. Absent on a route that sends
   *  none, and the row then keeps the link it has always shown. */
  analytic_exists?: boolean;
  weight_now: number;
  birth_weight: number;
  evidence: Record<string, unknown> | null;
}

/** One lead with its timeline, its live weight and its dismissal. */
export interface LeadDetail extends Lead {
  weight_now: number;
  single_signal: boolean;
  dismissed_reason: string | null;
  dismissed_note: string | null;
  dismissed_by: string | null;
  dismissed_at: string | null;
  investigation_id: string | null;
  dismiss_reasons: string[];
  observations: LeadObservationDetail[];
  /** The related leads, newest first. Absent on a route that sends none, and
   *  the page then shows no Related leads panel at all: an empty panel from a
   *  backend that computes nothing reads as "no related lead", which is an
   *  answer the deployment has not given. */
  related?: RelatedLead[];
}

/** Open leads, newest first, each with the observations that formed it. */
/** The status words the leads strip filters on. `closed` covers a dismissal
 *  and a promotion: both are a lead an analyst has finished with.
 *
 *  The spine adds two words that name what the analyst must do rather than
 *  what the record holds. `needs_decision` is a lead with no hunt, or a lead
 *  whose hunt has finished. `in_progress` is a lead whose hunt still runs. */
export type LeadStatusFilter =
  | 'open'
  | 'hunting'
  | 'dismissed'
  | 'promoted'
  | 'closed'
  | 'new'
  | 'all'
  | 'needs_decision'
  | 'in_progress';

export function getLeads(status: LeadStatusFilter = 'open'): Promise<Lead[]> {
  return request<Lead[]>(`/leads?status=${status}`);
}

/** One lead with its timeline and its live weight. */
export function getLead(id: number): Promise<LeadDetail> {
  return request<LeadDetail>(`/hunts/leads/${id}`);
}

/** What POST /hunts/leads/{id}/hunt answers. `existing` is "true" when the
 *  lead already held a hunt and the route returned that hunt unchanged. */
export interface LeadHuntStarted {
  hunt_id: string;
  existing?: string;
}

/** Start a hunt from the lead. A second call returns the same hunt. */
export function huntLead(id: number): Promise<LeadHuntStarted> {
  return post<LeadHuntStarted>(`/hunts/leads/${id}/hunt`, {}).then(leadChanged);
}

/** Reopen a dismissed or promoted lead. The lead returns to `open`. */
export function reopenLead(id: number): Promise<LeadDetail> {
  return post<LeadDetail>(`/hunts/leads/${id}/reopen`, {}).then(leadChanged);
}

/** Close the lead with a reason. The reason is required. */
export function dismissLead(id: number, reason: string, note?: string): Promise<LeadDetail> {
  return post<LeadDetail>(`/hunts/leads/${id}/dismiss`, { reason, note: note ?? null }).then(
    leadChanged,
  );
}

/** Start an investigation of the lead's strongest cited evidence. */
export function promoteLead(id: number): Promise<{ investigation_id: string }> {
  return post<{ investigation_id: string }>(`/hunts/leads/${id}/promote`, {}).then(leadChanged);
}

// ── Lead quality (the rule is instrumented, not moved) ───────────────────────
//
// The lead rule is a threshold, and a threshold nobody measures is a guess
// that hardened into a constant. This block is the measurement: what the rule
// produced per week, and which observation types produced it.
//
// The noise-floor rule the eval work landed applies here too: a threshold
// moves on a week of data, never on a day. The server sends that sentence in
// `note`, so the screen states the rule it is measured against.

/** One week of lead outcomes. `dismissed` is keyed by the reason the analyst
 *  chose, so a week with no dismissal carries an empty object rather than a
 *  row of zeroes for every reason the deployment knows. */
export interface LeadQualityWeek {
  week: string;
  formed: number;
  hunted: number;
  threat: number;
  promoted: number;
  dismissed: Record<string, number>;
}

/** One set of observation types, and what the leads they formed came to. */
export interface LeadQualityTypes {
  types: string;
  formed: number;
  dismissed: number;
  threat: number;
}

/** The lead quality block: the weeks, the type pairs, and the two sentences
 *  that say what the rule is and how it may be moved. */
export interface LeadQuality {
  weeks: LeadQualityWeek[];
  by_types: LeadQualityTypes[];
  /** The lead rule in one sentence, from the code that holds the constants. */
  rule: string;
  /** The noise-floor rule, in one sentence. */
  note: string;
}

/** The lead rule's own report, over the last `weeks` weeks. */
export function getLeadQuality(weeks = 4): Promise<LeadQuality> {
  return request<LeadQuality>(`/leads/quality?weeks=${weeks}`);
}

/** Every write on a lead moves the needs-you count. The emit sits here and not
 *  in the caller, so the strip, the lead page and the sidebar all get it. */
function leadChanged<T>(answer: T): T {
  emitNeedsYouChanged();
  return answer;
}


// ── Draft an analytic from a threat finding (merge 5) ────────────────────────
//
// The drafter writes one catalog analytic from the finding and its evidence.
// The server validates it, dry runs it over the last 30 days, and stores it in
// the local tier as a candidate. A candidate never runs until an analyst moves
// it to shadow.

/** The deterministic "would have fired" evidence attached to a drafted analytic. */
export interface AnalyticDryRun {
  ran: boolean;
  hit_count: number;
  sample_ids: string[];
  window_days: number;
  error: string | null;
}

/** One drafted analytic, already stored as a candidate. */
export interface AnalyticDraftResult {
  analytic_id: string;
  spec_yaml: string;
  rationale: string;
  dry_run: AnalyticDryRun;
  status: string;
}

/** Draft a catalog analytic from one threat hunt finding, by ordinal. */
export function draftAnalytic(huntId: string, ordinal: number): Promise<AnalyticDraftResult> {
  return post<AnalyticDraftResult>(
    `/hunts/${encodeURIComponent(huntId)}/findings/${ordinal}/draft-analytic`,
    {},
  );
}

// ── Analytics, shadow hits and observations (merge 4) ──────────────────────
//
// One analytic is one detection logic. The catalog reads two tiers: a shipped
// analytic is a file in the repository, and a local analytic is a row. An
// observation is one thing one analytic noticed about one entity. A shadow hit
// is an observation an analytic in shadow wrote.
//
// These land at the end of the file on purpose. Merge 5 edits the hunt agent
// and the hunt detail screen at the same time, and a shared tail keeps the two
// branches apart.

/** What a shadow analytic can prove about its own hit. The band renders the
 *  summary of this; the drawer renders the parts. `complete` false means the
 *  hit reads "could not run" and `missing` names the part. */
export interface ShadowHitReceipts {
  matched_ids: string[];
  matched_fields: string[];
  dry_run: { window_days: number; fires: number; entities: string[] } | null;
  overlap: Array<{ analytic: string; documents: number }>;
  baseline: Record<string, unknown> | null;
  complete: boolean;
  missing: string[];
}

/** GET /hunts/shadow-hits — one observation an analytic in shadow wrote.
 *  `state` is `hit` only when the receipts are complete. Anything else is
 *  `could_not_run`, which is never hidden and never shown as a hit. */
export interface ShadowHit {
  id: number;
  analytic_id: string;
  analytic_title: string;
  entity_kind: string;
  entity_key: string;
  born_at: string | null;
  /** When the analytic first wrote this observation. `born_at` moves with the
   *  newest sighting, so it answered "how old is this" with the wrong date. */
  first_seen_at?: string | null;
  /** How many times the analytic has written it. Absent on a route that sends
   *  none, and the card then states the time alone. */
  occurrences?: number;
  summary: string | null;
  state: string;
  missing: string[];
  receipts: ShadowHitReceipts | null;
  read: boolean;
  lead_id: number | null;
}

export interface ShadowHits {
  hits: ShadowHit[];
  unread: number;
}

/** GET /hunts/hits — every hit an analytic wrote in the window, live and
 *  shadow, in one list. A live hit is the real signal: its analytic runs, its
 *  hits count and they form leads. A shadow hit is provisional.
 *
 *  `read` is null on a hit recorded live, because such a hit has no read flag.
 *  `read_at` is optional: a server that does not send it makes the card state
 *  the read without an hour rather than invent one. */
export interface AnalyticHit {
  id: number;
  analytic_id: string;
  analytic_title: string;
  /** The status of the analytic now, from the catalog. A hit the sweep
   *  recorded in shadow reads `live` here once an analyst approves it. */
  analytic_status: 'live' | 'shadow' | 'candidate';
  /** True when the sweep recorded the hit while the analytic was in shadow.
   *  This is the flag that picks the half the hit lists under. */
  recorded_in_shadow: boolean;
  /** `shipped` is a file in the release. `local` is a row in this deployment. */
  tier: string;
  entity_kind: string;
  entity_key: string;
  born_at: string | null;
  first_seen_at: string | null;
  occurrences: number;
  summary: string | null;
  /** `hit` only when the receipts are complete. Anything else is
   *  `could_not_run`, which is never hidden and never shown as a hit. */
  state: string;
  missing: string[];
  receipts: ShadowHitReceipts | null;
  read: boolean | null;
  read_at?: string | null;
  lead_id: number | null;
  lead_status: string | null;
  document_count: number;
}

/** One count per filter chip. A chip states the number it would show. */
export interface AnalyticHitsCounts {
  all: number;
  unread: number;
  live: number;
  shadow: number;
}

export interface AnalyticHits {
  hits: AnalyticHit[];
  counts: AnalyticHitsCounts;
}

/** The four words the hit filter chips read. */
export type AnalyticHitFilter = 'all' | 'unread' | 'live' | 'shadow';

/** What waits on the analyst: unread shadow hits, and leads with no decision. */
export interface NeedsYou {
  unread_shadow_hits: number;
  leads_needing_decision: number;
  total: number;
  /** The live "A lead starts its own hunt" setting. Absent on an older server. */
  lead_auto_hunt?: boolean;
}

/** GET /analytics — one analytic with its tier, its status and a week of
 *  outcomes. `status` is one of candidate, shadow, live, retired. */
export interface AnalyticRow {
  id: string;
  title: string;
  level: string;
  evaluator: string;
  scope_kind: string;
  tier: string;
  status: string;
  no_benign_baseline: boolean;
  observations_7d: number;
  leads_7d: number;
  hunted_7d: number;
  dismissed_7d: number;
  shadow_hits_7d: number;
  unread_shadow_hits: number;
}

export interface AnalyticsList {
  analytics: AnalyticRow[];
  /** One count per status word. A status with no analytics is absent. */
  counts: Record<string, number>;
}

/** One status transition. The receipts an approval was taken on ride on the
 *  row, so "who approved this and why" stays answerable later. */
export interface AnalyticVersion {
  from_status: string | null;
  to_status: string;
  who: string;
  at: string;
  why: string | null;
  has_receipts: boolean;
}

/** The outcome ledger of one analytic over one window. Computed on read and
 *  never stored: a retirement taken on a stale figure retires the wrong
 *  analytic. */
export interface AnalyticLedger {
  analytic_id: string;
  since: string;
  observations: number;
  entities: number;
  shadow_hits: number;
  unread_shadow_hits: number;
  leads: number;
  hunted: number;
  promoted: number;
  dismissed: Record<string, number>;
  docs_scanned: number;
  runtime_ms: number;
  sweeps: number;
  coverage: Record<string, number>;
}

/** One entity this analytic observed lately, with the lead it fed. */
export interface AnalyticRecentEntity {
  entity: string;
  count: number;
  lead_id: number | null;
  last: string | null;
}

/** GET /analytics/{id} — the drawer's whole payload. */
export interface AnalyticDetail extends AnalyticRow {
  description: string;
  spec_text: string;
  reason: string | null;
  ledger: AnalyticLedger;
  versions: AnalyticVersion[];
  recent: AnalyticRecentEntity[];
}

/** One observation on one entity, from any source. `weight_now` decays with a
 *  48 h half-life and is computed on read. */
export interface EntityObservation {
  id: number;
  kind: string;
  spec_id: string;
  source: string;
  shadow: boolean;
  summary: string | null;
  weight_now: number;
  lead_id: number | null;
  born_at: string | null;
  occurrences: number;
  read: boolean;
  /** The label the server wrote for this kind. Absent on a route that sends
   *  none, and the table in lib/kinds.ts answers instead. */
  kind_label?: string | null;
}

export interface EntityObservations {
  entity: string;
  days: number;
  observations: EntityObservation[];
}

/** Shadow hits, unread first and then newest first. */
export function getShadowHits(limit = 50): Promise<ShadowHits> {
  return request<ShadowHits>(`/hunts/shadow-hits?limit=${limit}`);
}

/** Every analytic hit of the window, live first and then shadow, unread first.
 *  A parameter the caller leaves out is the server's default. */
export function getAnalyticHits(
  opts: { days?: number; filter?: AnalyticHitFilter; limit?: number } = {},
): Promise<AnalyticHits> {
  const query = new URLSearchParams();
  if (opts.days !== undefined) query.set('days', String(opts.days));
  if (opts.filter !== undefined) query.set('filter', opts.filter);
  if (opts.limit !== undefined) query.set('limit', String(opts.limit));
  const tail = query.toString();
  return request<AnalyticHits>(`/hunts/hits${tail ? `?${tail}` : ''}`);
}

/** The count the sidebar badge and the Needs-you strip read. */
export function getNeedsYou(): Promise<NeedsYou> {
  return request<NeedsYou>('/hunts/needs-you');
}

/** Mark one shadow hit read. Opening its receipts is what reads it. */
export function markShadowHitRead(id: number): Promise<{ ok: boolean }> {
  return post<{ ok: boolean }>(`/hunts/shadow-hits/${id}/read`, {}).then((answer) => {
    publishShadowHitsChanged();
    emitNeedsYouChanged();
    return answer;
  });
}

/** Every analytic the app lists, with a week of outcomes on each. */
export function getAnalytics(): Promise<AnalyticsList> {
  return request<AnalyticsList>('/analytics');
}

/** One analytic with its ledger, its versions and its recent observations. */
export function getAnalytic(id: string): Promise<AnalyticDetail> {
  return request<AnalyticDetail>(`/analytics/${encodeURIComponent(id)}`);
}

/** Store one local analytic as a candidate. It runs once it is in shadow. */
export function createAnalytic(specText: string): Promise<AnalyticRow> {
  return post<AnalyticRow>('/analytics', { spec_text: specText });
}

/** Move one analytic to a new status. A retirement needs a reason. An analytic
 *  that leaves shadow takes its unread hits with it, so the count changes. */
export function setAnalyticStatus(id: string, to: string, why?: string): Promise<AnalyticRow> {
  return post<AnalyticRow>(`/analytics/${encodeURIComponent(id)}/status`, {
    to,
    why: why ?? null,
  }).then((answer) => {
    emitNeedsYouChanged();
    return answer;
  });
}

/** Every observation on one entity from every source, newest first. */
export function getObservations(entity: string, days = 7): Promise<EntityObservations> {
  return request<EntityObservations>(
    `/hunts/observations?entity=${encodeURIComponent(entity)}&days=${days}`,
  );
}

/** GET /events/{id} — one document from the grid, as the sensor wrote it.
 *  `source` is the raw document body. A 404 carries reason `event_not_found`. */
export interface EventDocument {
  id: string;
  dataset: string | null;
  timestamp: string | null;
  source: Record<string, unknown>;
}

/** One document by its id. The evidence ids on a hit, a lead and a finding all
 *  read through this, so one id opens the same document everywhere. */
export function getEvent(id: string): Promise<EventDocument> {
  return request<EventDocument>(`/events/${encodeURIComponent(id)}`);
}

// ── Shadow-hit read events ──────────────────────────────────────────────────
//
// Four surfaces count one unread flag: the band, the bell, the sidebar badge
// and the Dashboard KPI. Each surface polls on its own timer. A hit read in
// the band stayed unread on the other three for up to 60 s, so the app showed
// two different counts of one number. The band publishes the change and every
// other surface reads the count again at once.

type ShadowHitsListener = () => void;

const shadowHitsListeners = new Set<ShadowHitsListener>();

/** Tell every surface that counts unread shadow hits to read the count again. */
export function publishShadowHitsChanged(): void {
  for (const listener of [...shadowHitsListeners]) listener();
}

/** Listen for a change to the unread shadow-hit count. Call the result to stop. */
export function onShadowHitsChanged(listener: ShadowHitsListener): () => void {
  shadowHitsListeners.add(listener);
  return () => {
    shadowHitsListeners.delete(listener);
  };
}

// ── Needs-you events ────────────────────────────────────────────────────────
//
// The sidebar badge and the Needs-you strip count one number: the unread shadow
// hits plus the leads that wait on a decision. A read hit, a hunt on a lead, a
// dismissal, a promotion, a reopen and an analytic that leaves shadow all move
// it. Each surface polls on its own timer, so without this the badge held the
// old count beside a page that had already changed.

const needsYouListeners = new Set<ShadowHitsListener>();

/** Tell every surface that counts what needs the analyst to read it again. */
export function emitNeedsYouChanged(): void {
  for (const listener of [...needsYouListeners]) listener();
}

/** Listen for a change to the needs-you count. Call the result to stop. */
export function onNeedsYouChanged(listener: ShadowHitsListener): () => void {
  needsYouListeners.add(listener);
  return () => {
    needsYouListeners.delete(listener);
  };
}
