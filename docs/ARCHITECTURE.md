# Architecture

This page describes how soc-ai is built. It goes deeper than the overview
diagram. It describes `main` as of the 1.5 line.

## Process model

- soc-ai runs as a single FastAPI process, async end to end. The entry point is
  `soc_ai/main.py`.
- The lifespan manager `lifespan()` in `main.py` builds every long-lived client
  once and stores it on `app.state`. The clients are the SO auth client, the
  Elasticsearch client, the optional MISP client, the audit logger, and the
  local-enrichment context. The local-enrichment context holds the blocklists,
  MaxMind and the cloud-prefix databases. soc-ai closes them all at shutdown.
- A request handler reads these clients off `app.state` through the providers in
  `soc_ai/api/deps.py`. `get_investigation_ctx` assembles a fresh
  `InvestigationContext` for each request. That context shares the app-scoped
  clients.
- Application state persists in a local SQLite database under `soc_ai/store/`,
  with Alembic migrations. It holds the users, sessions, API tokens,
  investigations, hunts, backtests, chat threads, config overrides, discovered
  internal identifiers, detection overrides, and operator runbooks.
- The local database does not hold the audit trail. soc-ai writes the
  tamper-evident audit trail to Elasticsearch. The application cannot edit that
  index in place. Read *Audit pipeline* below.

## Request surface (`soc_ai/api/routes.py`)

| Route | Purpose |
|---|---|
| `POST /investigate` | Streams a triage as Server-Sent Events. Each message holds `event: {kind}` and a JSON `StepEvent` payload. |
| `POST /find-alert` | Resolves an ES `_id` from row-level context that a cross-origin API client supplies. SO 3.0 does not embed an `_id` in the DOM. |
| `GET /healthz` | Liveness only. It says that this process answered. It probes no dependency, so it stays green through a grid outage or a gateway outage. The container healthcheck polls it, so `docker ps` reporting `healthy` says nothing about the product. It carries a minimal config snapshot for a bug report: the auth mode, and whether MISP is configured. For the health verdict use `GET /api/v1/health` or `soc-ai doctor`. |
| `GET /metrics` | Prometheus 0.0.4 plain-text exposition. The code is `soc_ai/metrics.py`. |

The write actions are not on this surface. A write action acknowledges an alert,
escalates it to a case, or comments on it. The pipeline recommends them in
the report. The analyst executes them through the actions API at
`POST /api/v1/investigations/{id}/actions/{index}/execute`. That route lives in
`soc_ai/api/webui/routes_actions.py`, and it is the single analyst write path.

> **Security posture:** the JSON API requires authentication if
> `API_AUTH_REQUIRED=true`. It accepts a session cookie from the web login, or a
> bearer API token as `Authorization: Bearer scai_…`. `require_api_auth` in
> `soc_ai/api/security.py` enforces this. An admin-only route sits behind a
> separate admin gate.
>
> CORS is scoped to `CORS_ALLOW_ORIGINS`, and it falls back to the configured
> `SO_HOST`. `"*"` is a last-resort fallback only, and `soc_ai/main.py` logs a
> warning for it. Deploy soc-ai behind TLS on a trusted interface. Read
> `docs/SAFETY_MODEL.md` and `SECURITY.md`.

## The triage funnel

Every triage runs through one entry point, `investigate()` in
`soc_ai/agent/orchestrator.py`. That function delegates to
`_run_synth_first_pipeline()`. There is one pipeline with staged escalation. Each
stage handles what the stage before it could not, at about 10 times the cost.

```mermaid
flowchart TD
    A[Alert] --> B[Prefetch + local enrichment<br/><i>deterministic, no LLM</i>]
    B --> C[Phase B: decision template<br/><i>→ optional candidate anchor</i>]
    C --> DI{"skip round 1?<br/><i>definitely-investigate: malware/exploit signal,<br/>threat-context flag, provisional template<br/>· cannot-settle: no dispositive FP template</i>"}
    DI -- yes → synth_round1_skipped --> G[Investigation loop<br/><i>LLM agent, full read-tool surface</i>]
    DI -- no --> D[Synthesis round 1<br/><i>LLM, <b>no tools</b>, the verdict writer</i>]
    D -- confident --> R2[TriageReport]
    D -- names ONE gap --> E[Phase D: targeted dispatch<br/><i>deterministic: runs exactly the tool+args the synth named</i>]
    E --> F[Synthesis round 2] --> R3[TriageReport]
    D -- investigate_when_unsure trigger --> G
    G --> H[Synthesizer over transcript] --> R4[TriageReport]
    R2 & R3 & R4 --> I[Deterministic gates<br/>citation validation · evidence gate ·<br/>malware-label payload gate · downgrades]
    I --> J{Oracle escalation?<br/><i>opt-in 2nd opinion, raw HTTP</i>}
    J --> K[Final report + recommended actions<br/><i>analyst executes write tools on demand</i>]
```

### Role glossary

The name in the code, and the real role:

| Code name | Actual role |
|---|---|
| `build_synth_first_agent` ("synthesizer") | The primary verdict writer on the settle path. It has no tools by design. The loop path uses the sibling `build_synthesizer` over the transcript. A failure path emits a deterministic fallback. |
| `targeted_investigator` / Phase D | A deterministic dispatcher. It is no agent and no LLM. It runs the one tool that the synth named. The code is `soc_ai/agent/targeted_investigator.py`. |
| `build_investigator` | The investigation loop. It is a full tool-equipped agent. It is entered on a definitely-investigate decision, on an `investigate_when_unsure` trigger, or on `fast_triage_enabled=false`. That setting forces the loop for every alert. |
| Chat / Hunt agents | They share the read-tool surface from `soc_ai/agent/toolset.py`. Chat adds `propose_verdict` and rule tuning. Hunt uses wider windows and writes a `HuntReport`. |
| Oracle | An opt-in second opinion over a raw HTTP completion. It is not a pydantic-ai agent. |

### Synth-first stage detail

- **Phase A, rich precompute:** `get_enriched_alert_context()` pivots the alert
  across the host, the user and the community ID. It runs local enrichment and
  produces an `EnrichedAlertContext`.
- **Phase B, decision template:** `match_decision_template()` in
  `soc_ai/agent/decision_templates.py` runs ordered pure-function templates over
  the enriched context. It can hand the synth a *candidate verdict*. That
  candidate is an anchor, and the synth can keep it, refine it or override it.
- **The definitely-investigate check, before Phase C:** `_definitely_investigate()`
  tests 3 triggers: a malware or exploit signal on the rule, a concurrent host
  threat-context flag, or a provisional benign decision-template match. This
  pre-check runs only if `investigate_when_unsure` is enabled. If the check is
  true, soc-ai emits a `synth_round1_skipped` event and routes straight to the
  investigation loop. Phase C never runs.
- **The cannot-settle check, beside it:** `_round1_can_settle()` asks whether a
  round-1 verdict could end the run at all. Only a dispositive false-positive
  template lets it. Round 1 has no tools and no message history, so
  `_is_evidence_backed()` rejects every round-1 report. On every other alert the
  loop runs and overwrites the round-1 verdict. soc-ai therefore skips the call.
  It emits `synth_round1_skipped` with reason `cannot_settle`, and it enters the
  loop with `loop_reason="round1_cannot_settle"`. The same function decides
  whether `_should_investigate()` accepts a round-1 verdict, so the two cannot
  disagree. The check yields if nothing else would produce a verdict.
  That is the `investigate_when_unsure=false` case with no forced loop. The
  `synth_round1_always` setting restores the call on every alert.
- **Template authority:** a candidate verdict is `dispositive` or `provisional`.
  A dispositive template reads what the rule detected, such as STUN and QUIC
  keepalives, DNSSEC record queries and NTP. It can settle an alert with no tool
  call, and that fast path is the reason decision templates exist. A provisional
  template reads a property of the endpoints, or the absence of a reputation hit.
  `clean_internal_traffic` and the two external-reputation templates are
  provisional. A provisional template proposes a verdict, steers the routing, and
  reaches the synthesizer as a prior. It cannot close a case. The default is
  `provisional`.
- **Phase C, synthesis round 1:** the model reads the materialized evidence and
  the candidate. Then it emits a `TriageReport`. It has no tools. The report can
  include a `gap_for_investigator` that names one tool and its exact arguments.
- **Phase D, targeted dispatch, optional:** Phase D runs if the report named a
  gap and the pipeline did not enter the loop. `soc_ai/agent/targeted_investigator.py`
  then dispatches that single tool deterministically, with no model call.
  Synthesis round 2 then reads the combined evidence. Phase D runs at most
  `phase_d_max_rounds` rounds of gap, dispatch and re-synthesize. The default is
  1. On a round that is not the last one, the synth can chain one more gap, for
  example `t_get_event_raw` and then `t_decode_payload`.
- **The investigation loop, optional:** it is a full tool-equipped agent. Any of
  4 conditions enters it. `_definitely_investigate` returned true, and the loop
  then skipped round 1. `_round1_can_settle` returned false, and the loop again
  skipped round 1. `_should_investigate` triggers on an evidence gap with the
  `investigate_when_unsure` setting on. `fast_triage_enabled=false` forces
  the loop for every alert, whatever the round-1 confidence, with loop_reason
  `"fast_triage_disabled"`. The synthesizer then runs over the full transcript.

Every report passes through the post-synth validators before soc-ai emits the
final report. Read the section below.

## Budget classes and the ladder

A triage run has a budget class. The class says how much the run may spend. The
console shows it as a chip on the Investigations list, the drawer and the page.
The run row stores it in `run_class`.

| Class | What the run does | Who gets it |
|---|---|---|
| `rule_prior` | No model call. The alert takes the verdict of its rule's latest model run. | The scheduler, when the rule prior covers the alert in live mode. |
| `cheap` | One synthesis request on the prefetch. No tool loop. No Oracle. | The scheduler, when a dispositive template cleared the alert. |
| `standard` | The tool loop at the standard budget. The prompt and the tool schemas fit the alert. | An analyst's Investigate, a re-run, a bulk selection, a promotion, a hunt. The scheduler for every other alert. |
| `deep` | The tool loop with the whole prompt and every tool schema. | The analyst's Deep re-run. |

The rungs of the ladder run in order. Each rung is cheaper than the next. A
step runs only if a cheaper step did not decide the alert.

1. **Inheritance:** a model verdict on the same rule, source, destination and
   host in the last 7 days covers the alert. A pipeline fallback and a
   rule-prior run never lend a verdict.
2. **Rule prior:** read the next section.
3. **Decision template:** a dispositive template plans the cheap class.
4. **Cheap:** round 1 writes the verdict. A verdict that is not a false
   positive escalates the run to standard. A verdict that a verdict gate would
   change escalates it too, before the gate runs.
5. **Standard:** the loop runs.
6. **Deep:** the loop runs with every section and every tool.

The class the row stores is the class that ran. A planned cheap run that
entered the loop is standard. The report carries the reason in
`run_class_reason`.

### The rule prior

The rule prior covers a scheduled alert with the verdict of its rule's latest
model run. It is the one rung that can hide a new case, so six safeguards hold
it. The code is `soc_ai/agent/rule_prior.py`.

1. Both endpoints are inside the estate. An alert with an external endpoint or
   with no flow always runs.
2. The rule has `rule_prior_min_runs` model false positives in the last 7 days.
   The minimum is 5. No other model verdict of the rule falls in that window.
   One run is less than 24 hours old, so every rule gets one real run a day.
3. Neither host carries an open lead or an observation newer than 24 hours.
4. The alert is not critical and carries a severity label. Detection tuning
   nominates the rule. No analyst ever overrode a verdict of the rule.
5. A rule-prior run records no recommended action. It never acknowledges in
   Security Onion.
6. A random share of covered alerts still gets a real run. The share is
   `rule_prior_sample_rate`, 0.02 by default. A real run that disagrees with the
   prior suspends it for the rule. An analyst clears the suspension on the
   Detection tuning panel.

`rule_prior_mode` is `off`, `shadow` or `live`. A change applies with no restart.
`shadow` is the default. In `shadow`, the model runs as before. The `rule_prior_decisions` table records
what the prior would decide, why it did or did not apply, and the real verdict.
In shadow every covered alert gets a real run, so every disagreement suspends
the rule. In `live` a covered alert that the sample did not pick gets a
rule-prior run and no model call. The Detection tuning panel shows the covered
alerts, the agreements, the disagreements and the suspension per rule.

### The standard loop

The pipeline runs the web search that the loop used to spend a turn on. If an
external indicator has no enrichment answer, the pipeline searches it before
the loop. It puts the result in the loop's message. The loop does not repeat
the search. A failed search leaves the condition, and the loop can still search.

The standard class sends the prompt sections and the tool schemas that the
alert's planes make useful. A plane is a fact about the prefetch. The planes are
a flow, an external endpoint, an internal pair, host logs or an attack-class rule,
a payload, a file hash, ICMP and a decoy. A flow to the internet gets no Kerberos
rule and no PsExec example. The other investigator tools stay registered with
deferred loading. The loop's message names them. One `search_tools` call loads
a tool for the next turn. The deep class keeps the whole prompt and every
schema.

### The Oracle

The setting `oracle_rule_mode` selects the rule that sends a verdict to the
Oracle. The default is `shadow`.

- `classic` is the verdict-class rule from before stage 1. It sends a
  needs_more_info verdict, a verdict other than true_positive on a malware or
  attack rule, and a confidence below 0.6. Its reasons are `needs_more_info`,
  `malware_non_tp` and `below_confidence`.
- `uncertainty` sends an uncertain verdict. It never sends a verdict because of
  its class alone.
- `shadow` lets the classic rule decide. The run also records an
  `oracle_shadow` event with the reason that the uncertainty rule would give.
  No Oracle call comes from that event. Detection tuning shows the tally of the
  last 7 days.

Three reasons send a verdict under the uncertainty rule:

- `confidence_in_band`: the confidence is in the gate band, from 0.4 to below
  0.7. A coercing gate parks a verdict it could not ground at 0.4. The gates let
  a verdict at 0.7 stand as confident.
- `template_split`: the decision template and the model disagree.
- `deep_needs_more_info`: a deep run ended with needs_more_info.

A verdict that the template and the model agree on at 0.7 or above never goes
to the Oracle. A cheap run and a rule-prior run never go under either rule. The opt-ins
`oracle_escalate_needs_more_info`, `oracle_escalate_malware_non_tp`,
`oracle_skip_after_confident_loop` and `oracle_escalate_below_confidence` narrow
both rules. They never add an escalation. The `oracle_escalation` audit row names
the reason and the rule mode.

An Oracle verdict that changes the local verdict needs evidence. The Oracle
must cite an id that resolves to evidence that the local run retrieved beyond
the alert. That evidence is a prefetched event or a document in the tool results
of the loop. With the
tool loop on, a successful tool call of its own also counts. Without evidence,
the `oracle_adjudication` row records the answer as an opinion with
`override_withheld`. The local verdict stands, and the auto-acknowledge never
fires on that run. A citation resolves only by membership in the retrieved ids.
A substring of the payload text does not count.

A failed adjudication writes an `oracle_adjudication_failed` row with the HTTP
status, the error class and the gateway's message. The message is
secret-scrubbed. The classes are `quota`, `5xx`, `4xx`, `timeout`, `transport`,
`refused`, `unparseable`, `serialization`, `blocked` and `paused`. The reason
`no_parseable_verdict` means that the last attempt got a 200 with no verdict in
the body.

The Oracle route pauses if the gateway answers with a usage limit, or with
three server errors in a row. A route is the gateway URL and the Oracle model.
The pause lasts until the reset time that the message or the `Retry-After`
header names. With no reset time, the pause lasts one hour. During the pause soc-ai makes no Oracle call. It
writes an `oracle_skipped` row for each escalation, with the reset time, and
the local verdict stands. The doctor and the preflight show an "oracle route"
row. The bell gets one row for each pause, and the webhook gets one message.
`notify_on_oracle_failure` turns both off.

### Run counters

Every triage run, hunt and lead hunt stores what it cost. The record holds the
model requests, the input and output tokens, the tool calls, the Elasticsearch
searches, the wall time and the class. `soc-ai usage --days N` prints the table per entry
point. An older run reads its tokens and its tool calls from its stored events.
A number the store does not hold prints as a dash.

## Models & routing

- soc-ai reaches a model through a LiteLLM gateway over an OpenAI-compatible
  surface. The code is `_build_provider` and `build_*_model` in
  `soc_ai/agent/models.py`. A Nemotron-specific model profile,
  `_nemotron_profile`, adjusts the tool-call behavior for the served models.
- A single analyst model feeds the investigator, the synthesizer, the hunt agent
  and the chat agent. `ANALYST_MODEL` names it, and `HEAVY_MODEL` is the
  legacy alias. The code reads `settings.analyst_model` in
  `soc_ai/agent/models.py`. The pre-1.0 split into a fast model and a heavy model
  is gone. The opt-in Oracle is the only second model. soc-ai reaches it over raw
  HTTP, outside the pydantic-ai path.

## Tools & the read/write split

soc-ai registers every tool function in a global registry,
`soc_ai/tools/_registry.py`, with a `read_only` flag. `soc_ai/agent/toolset.py`
owns the read-tool surface alone. It owns the wrapping, the dedup, the result
clamping and the per-role registration. It defines every `t_*` tool once and
exposes them per role through `register_read_tools(agent, ctx, role)`. Closures
over the runtime `InvestigationContext` keep the model-facing signatures semantic,
so no `auth` or `elastic` parameter reaches the schema.

- **Read tools** auto-execute. They include `t_query_events_oql`,
  `t_query_cases`, `t_query_detections`, `t_query_zeek_logs`, `t_get_playbooks`,
  `t_get_event_raw`, the `t_enrich_*` family, `t_lookup_runbook`, and more.
- **Write tools** are `ack_alert`, `escalate_to_case` and `add_case_comment`.
  soc-ai never exposes them to the model for execution. The report *recommends*
  them. They run only through the audited `execute_write_tool` in
  `soc_ai/tools/write_exec.py`, on an explicit analyst action.

A tool wrapper clamps the result size and `max_results` to protect the context
window of the model. It dedupes an identical call inside one run. It translates
an exception into a structured error payload and keeps the stream alive. The
dispatchable surface of Phase D is the `PHASE_D_TOOLS` tuple that `toolset.py`
exports.

## OQL trust boundary (`soc_ai/so_client/oql.py`)

This module is the boundary between a model-generated query string and
Elasticsearch. Raw OQL never reaches ES. The pipeline is:

1. `parse_oql` splits the query on the top-level `|`. It parses the boolean
   filter into a typed AST with a Lark grammar. It parses the pipe stages with a
   regex.
2. `validate_oql` walks the AST. It rejects any field that the whitelist
   `oql_fields.json` does not hold. It rejects a repeated or unsafe pipe stage.
   It caps `head` at a hard ceiling of 10,000 rows.
3. `ast_to_es_dsl` translates the validated AST into an ES search body.

`query_events_oql` also excludes synthetic-eval documents by default. It matches
them on `synth.scenario_id`, so no fixture leaks into a real response.

## Write-action flow (`soc_ai/tools/write_exec.py` → `execute_write_tool`)

1. The pipeline never executes a write itself. It lists the write tools in
   `TriageReport.recommended_actions`, and that list is advisory.
2. The analyst executes a recommendation from the report through the actions API
   at `POST /api/v1/investigations/{id}/actions/{index}/execute`. The group
   acknowledge, the group escalate and the auto-acknowledge use the same path.
   The auto-acknowledge is off by default. It gates on the confidence, the
   severity, and whether the run retrieved anything. Set
   `auto_ack_fp_enabled=true` to enable it.
3. Every execution runs through `execute_write_tool`. It accepts the 3 write
   tools only. It audits fail-closed, so soc-ai writes the audit *intent* record
   before it touches Security Onion. It is idempotent for an action that already
   ran. A persisted `action_executed` event, or an already-acked alert, returns
   ok-with-note, and soc-ai does not write twice.

[SAFETY_MODEL.md](SAFETY_MODEL.md) holds the full specification.

## Post-synth validators

The pipeline runs a model-agnostic validator chain on the final report before it
emits the report. The chain is `_synth_first_post_validate` in
`soc_ai/agent/gates.py`. It runs citation validation and capping. It runs a
verdict floor rewrite, so a sub-floor confidence becomes `needs_more_info`. It
runs targeted downgrades, for example on a solicited internal ICMP echo reply. It
runs the malware-label payload gate, GATE A. It runs the hard evidence gate. A
verdict with no tool call, no dispositive template that cites its grounds, and no
IOC or pivot hit becomes `needs_more_info`.

These validators are graders. They reshape the report deterministically, and
they never retry the model.

The chain deliberately treats 2 things as no evidence at all. Coverage over an
empty citation set reads `0.0` with a `vacuous` marker. A report that cites
nothing therefore meets no coverage threshold. The confidence cap skips the
vacuous case. The evidence gate handles a report that cited nothing. A template that settles an alert must also have its
grounds on the record. A dispositive template therefore lends its own
`cited_evidence` to a report that cited nothing, and the marker is
`template_grounds_adopted`.

## Reasoning-trace handling (`soc_ai/agent/reasoning.py`)

A served reasoning model emits `<think>…</think>` blocks. The reasoning module
strips them from the user-facing content and routes them to the audit trail. With
`AUDIT_REDACT` on, they pass through the redactor first. The panel summary never
shows a trace.

## Audit pipeline (`soc_ai/audit/`)

`AuditLogger` mirrors every `StepEvent` to a date-stamped Elasticsearch index,
`{AUDIT_INDEX_ALIAS}-YYYY.MM.dd`. An audit write fails open. soc-ai logs a
write error locally and drops the event, and the in-flight investigation
continues. A local fallback queue is a noted follow-up. Optional regex redaction
in `audit/redact.py` runs in place if `AUDIT_REDACT=true`.
[SAFETY_MODEL.md](SAFETY_MODEL.md) holds the schema and the redaction policy.

## MCP server (`soc_ai/mcp_server/`)

A FastMCP server exposes the read-only tool subset to an MCP client. Start it
with `python -m soc_ai.mcp_server`. It never registers the 3 write tools. It
reuses the same tool functions as the FastAPI path.

## Local enrichment (`soc_ai/enrichment/`)

Local enrichment makes no call at runtime. soc-ai loads the blocklists, the
MaxMind GeoLite2 databases and the vendored cloud-provider prefix lists from
disk. The blocklists are URLhaus, ThreatFox, Feodo, the Tor exit list and the
operator seed. MaxMind GeoLite2 supplies the ASN database and the City database.
The operator downloads those two files by hand.

The `soc-ai blocklists refresh` CLI subcommand refreshes the blocklists and the
cloud prefixes.

Every enrichment source is wrapped, so a missing or stale source degrades triage
and never blocks it. MISP is the one optional network lookup, if you configure
it.

## Offline eval harness (`soc_ai/eval/`)

The harness sits outside the request path. It samples real alerts, and it can
inject synthetic true-positive scenarios into a lab index. It runs the triage
pipeline, sanitizes the output, and grades it against the Oracle. It reaches
the Oracle through the same LiteLLM gateway. This harness is the only
component that calls a third-party model. That call is opt-in, and soc-ai
sanitizes and refuse-gates the data before it leaves.

[`soc_ai/eval/synth_scenarios/README.md`](https://github.com/nuk3s/soc-ai/blob/main/soc_ai/eval/synth_scenarios/README.md)
documents the synthetic-scenario catalogue that the harness can inject.
