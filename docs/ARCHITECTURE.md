# Architecture

How soc-ai is put together, going deeper than the high-level diagram in the
README. This describes `main` as it stands after the v1 delivery.

## Process model

- A **single FastAPI process**, async end-to-end (`soc_ai/main.py`).
- All long-lived clients are constructed **once** in the lifespan manager
  (`lifespan()` in `main.py`) and stashed on `app.state`: the SO auth client,
  the Elasticsearch client, the optional MISP client, the in-memory approval
  gate, the audit logger, and the local-enrichment context (blocklists +
  MaxMind + cloud-prefix DBs). They are torn down on shutdown.
- Request handlers pull these off `app.state` via the providers in
  `soc_ai/api/deps.py`. A fresh `InvestigationContext` is assembled per request
  (`get_investigation_ctx`) but shares the app-scoped clients.
- Application state persists in a local SQLite database (`soc_ai/store/`, Alembic
  migrations): users, sessions, API tokens, investigations, hunts, backtests,
  chat threads, config overrides, discovered internal identifiers, detection
  overrides, and operator runbooks. The tamper-evident audit trail is written
  separately to Elasticsearch (see *Audit pipeline*), so the immutable log lives
  on an index the application cannot edit in place.

## Request surface (`soc_ai/api/routes.py`)

| Route | Purpose |
|---|---|
| `POST /investigate` | Streams a triage as Server-Sent Events. Each message is `event: {kind}` + a JSON `StepEvent` payload. |
| `POST /approve` | Applies a user's decision to a pending write-tool call; executes the tool exactly once on approval. |
| `POST /find-alert` | Resolves an ES `_id` from row-level context supplied by a cross-origin API client (SO 3.0 doesn't embed `_id`s in the DOM). |
| `GET /sessions/{id}` | Lists pending approvals (v1 has a single global gate; the id is informational). |
| `GET /healthz` | Liveness + a minimal config snapshot (auth mode, MISP configured, pending-approval count). |
| `GET /metrics` | Prometheus 0.0.4 plain-text exposition (`soc_ai/metrics.py`). |

> **Security posture:** the JSON API requires authentication when
> `API_AUTH_REQUIRED=true`: a session cookie (web login) or a bearer API token
> (`Authorization: Bearer scai_…`), enforced by `require_api_auth`
> (`soc_ai/api/security.py`); admin-only routes sit behind a separate admin gate.
> CORS is scoped to `CORS_ALLOW_ORIGINS` (else the configured `SO_HOST`), with
> `"*"` only as a last-resort fallback that logs a warning (`soc_ai/main.py`).
> Still deploy behind TLS on a trusted interface; see `docs/SAFETY_MODEL.md`
> and `SECURITY.md`.

## The two triage pipelines

soc-ai ships **two** orchestration strategies behind one entry point,
`investigate()` in `soc_ai/agent/orchestrator.py`. The
`SYNTH_FIRST_PIPELINE` setting (default **on**) selects between them.

### Legacy two-stage (investigator → synthesizer)

1. **Prefetch** the alert context and embed it in the investigator's prompt.
2. **Investigator** (fast model) gathers evidence with the read tools, emitting
   an `InvestigationTranscript`.
3. **Synthesizer** (heavy model) reads the transcript and emits a typed
   `TriageReport` (verdict + confidence + citations + recommended actions).
4. If the synthesizer's confidence is below `SYNTHESIS_CONFIDENCE_FLOOR`, the
   investigator is **retasked once** with the synthesizer's open questions and
   the synthesizer runs again. The retask is capped at one round.

### Synth-first (A → B → C → optional D → C round 2)

The current default (`_run_synth_first_pipeline()`), introduced to cut the
fast model's large reasoning-trace overhead out of the common path:

- **Phase A — rich precompute:** `get_enriched_alert_context()` pivots the
  alert across host / user / community-id and runs local enrichment, producing
  an `EnrichedAlertContext`.
- **Phase B — decision template:** `match_decision_template()`
  (`soc_ai/agent/decision_templates.py`) runs ordered, pure-function templates
  over the enriched context and may hand the synth a *candidate verdict* (an
  anchor it can keep, refine, or override).
- **Phase C — synthesis round 1:** the heavy model reads the materialized
  evidence + candidate and emits a `TriageReport`. It may include a
  `gap_for_investigator` naming **one** tool + exact args.
- **Phase D — targeted investigator (optional):** if a gap was named, dispatch
  that single tool **deterministically** (no LLM in the loop;
  `soc_ai/agent/targeted_investigator.py`), then run synthesis round 2 on the
  combined evidence. Phase D runs at most once.

Both pipelines converge on the same **post-synth validators** before emitting
the final report (see below).

## Models & routing

- Models are reached through a **LiteLLM gateway** via an OpenAI-compatible
  surface (`_build_provider` / `build_*_model` in `soc_ai/agent/models.py`). A
  Nemotron-specific model profile (`_nemotron_profile`) adjusts tool-call
  behavior for the served models.
- Two aliases: a **fast** model (investigator / Phase D in the legacy path) and
  a **heavy** model (synthesizer). In the synth-first default only the heavy
  model is called per alert.
- A **rule-class fast-path** (`ENABLE_RULE_CLASS_FAST_PATH`) routes
  informational-visibility / low-severity alerts through a stripped-down
  confirm-or-deny prompt with a tighter tool budget and a small sampling rate
  back through the full pipeline for drift monitoring.

## Tools & the read/write split (`soc_ai/tools/`)

Every tool function is registered in a global registry (`tools/_registry.py`)
with a `read_only` flag and exposed to the agent as a closure that captures the
`InvestigationContext` (so the LLM-facing signature stays semantic: no
`auth`/`elastic` params leak into the schema).

- **Read tools** (`query_events_oql`, `query_cases`, `query_detections`,
  `query_zeek_logs`, `get_playbooks`, `get_alert_context`, the `enrich_*`
  family, `lookup_runbook`) auto-execute.
- **Write tools** (`ack_alert`, `escalate_to_case`, `add_case_comment`) **must**
  pass through the `ApprovalGate` before the underlying function runs.

Tool wrappers clamp result sizes and `max_results` to defend the model's
serving window, dedupe identical calls within a run, and translate exceptions
into structured error payloads rather than crashing the stream.

## OQL trust boundary (`soc_ai/so_client/oql.py`)

This is the firewall between LLM-generated query strings and Elasticsearch.
Raw OQL **never** reaches ES. The pipeline is:

1. `parse_oql` — split on top-level `|`, parse the boolean filter with a Lark
   grammar into a typed AST, parse pipe stages with regex.
2. `validate_oql` — walk the AST and reject any field not on the whitelist
   (`oql_fields.json`), reject repeated/unsafe pipe stages, and cap `head` at a
   hard 10,000-row ceiling.
3. `ast_to_es_dsl` — translate the validated AST into an ES search body.

`query_events_oql` also excludes synthetic-eval docs
(`synth.scenario_id`) by default so fixtures can't leak into real responses.

## Approval flow (`soc_ai/tools/_registry.py` → `ApprovalGate`)

1. When the agent wants a write tool, the orchestrator calls
   `gate.request(...)` to mint a token, surfaces it over SSE, and raises
   `ApprovalRequired`.
2. The user `POST /approve {token, approved}` → `gate.decide(...)`.
3. On approval the route calls `gate.consume(...)`, which atomically transitions
   the request to `consumed` (single-execution guarantee even under duplicate
   `/approve` retries), then invokes the tool function once.

The gate is `asyncio.Lock`-guarded and idempotent on repeated decisions. Full
spec in [SAFETY_MODEL.md](SAFETY_MODEL.md).

## Post-synth validators

Both pipelines run a model-agnostic validator chain on the final report before
emission (`_synth_first_post_validate` and the legacy equivalent in
`orchestrator.py`): citation validation + capping, a template-confidence
ceiling (a synth can't exceed its template anchor's confidence without
evidence), a verdict floor rewrite (sub-floor confidence → `needs_more_info`),
and targeted downgrades (e.g. solicited internal ICMP echo replies). These are
**graders, not gatekeepers**: they reshape the report deterministically rather
than retrying the model.

## Reasoning-trace handling (`soc_ai/agent/reasoning.py`)

Served reasoning models emit `<think>…</think>` blocks. The reasoning module
strips these from user-facing content and routes them to the audit trail (and,
when `AUDIT_REDACT` is on, through the redactor). Traces are never shown in the
panel summary.

## Audit pipeline (`soc_ai/audit/`)

Every `StepEvent` is mirrored to a date-stamped Elasticsearch index
(`{AUDIT_INDEX_ALIAS}-YYYY.MM.dd`) via `AuditLogger`. Audit writes **fail open**:
a write error is logged locally and the event is dropped rather than crashing
the in-flight investigation (a local fallback queue is a noted follow-up).
Optional regex redaction (`audit/redact.py`) runs in-place when
`AUDIT_REDACT=true`. Schema and redaction policy: [SAFETY_MODEL.md](SAFETY_MODEL.md).

## MCP server (`soc_ai/mcp_server/`)

A FastMCP server (`python -m soc_ai.mcp_server`) exposes the **read-only** tool
subset to MCP clients; the three write tools are never registered. It reuses
the same tool functions as the FastAPI path.

## Local enrichment (`soc_ai/enrichment/`)

No runtime egress: blocklists (URLhaus / ThreatFox / Feodo / Tor exit list /
operator seed), MaxMind GeoLite2 (ASN + City), and vendored cloud-provider
prefix lists are loaded from disk and refreshed by the
`soc-ai blocklists refresh` CLI subcommand. Every enrichment source is wrapped
so a missing/stale source degrades rather than blocks triage. MISP, if
configured, is the one optional network lookup.

## Offline eval harness (`soc_ai/eval/`)

Out of the request path. It samples real alerts (and optionally injects
synthetic true-positive scenarios into a lab index), runs the triage pipeline,
sanitizes the output, and grades it against the cloud oracle reached through the
same LiteLLM gateway. This is the **only** component that makes an external
(third-party model) call, it is opt-in, and the data is sanitized and
refuse-gated before it leaves. The synthetic-scenario catalogue it can inject is
documented in [`soc_ai/eval/synth_scenarios/README.md`](https://github.com/nuk3s/soc-ai/blob/main/soc_ai/eval/synth_scenarios/README.md).
