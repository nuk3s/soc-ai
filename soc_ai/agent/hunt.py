"""Chat-driven threat-hunt agent (Hunt Console).

A Hunt is broader than an Investigation: instead of dispositioning ONE alert
into a verdict, it investigates across multiple alerts / hosts / time — or a
free-form objective the analyst types in plain language ("hunt for beaconing to
rare external IPs", "look for credential-abuse lockouts") — and produces
**findings + a narrative**, mapped to MITRE ATT&CK.

The agent's read-tool surface comes from
:func:`soc_ai.agent.toolset.register_read_tools` (role ``"hunt"``): the
**minimal** role surface — verdict-adjacent tools (detections, playbooks,
runbook, rule-tuning) are excluded, and the windowed query tools default to a
24-hour window because a hunt looks across time rather than centering on a
single alert's ``@timestamp``. What else differs from the investigator:

- a **hunt-oriented system prompt** — correlate across hosts/time, map to MITRE,
  report findings + a narrative rather than a single-alert verdict;
- a structured :class:`HuntReport` output schema.

Read-only in this phase — a hunt never acks/escalates/opens a case (no write
tools, no Oracle), exactly like the "Chat about this" agent.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field
from pydantic_ai import Agent
from pydantic_ai.models import Model

from soc_ai.agent.orchestrator import InvestigationContext
from soc_ai.agent.toolset import register_read_tools

# =====================================================================
# Output schema
# =====================================================================


class HuntFinding(BaseModel):
    """One discrete thing the hunt turned up, backed by evidence."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(
        description=(
            "Short headline for the finding (analyst-scannable). HARD STYLE RULE: "
            "max ~8 words / 60 characters, no trailing punctuation."
        )
    )
    detail: str = Field(
        description="2-4 sentences: what was observed and why it matters, grounded in tool results."
    )
    severity: str = Field(
        default="info",
        description="One of 'info' | 'low' | 'medium' | 'high' | 'critical'.",
    )
    category: str = Field(
        default="threat",
        description=(
            "What KIND of finding this is: 'threat' (observed malicious or "
            "suspicious activity), 'visibility_gap' (telemetry that does not "
            "exist on this grid, so the objective can't be confirmed or ruled "
            "out), or 'observation' (benign/informational context). A missing "
            "dataset is ALWAYS 'visibility_gap', never 'threat' — severity on "
            "a gap grades how badly it blinds the objective, not maliciousness."
        ),
    )
    hosts: list[str] = Field(
        default_factory=list,
        description="Internal hosts/IPs this finding concerns.",
    )
    citations: list[str] = Field(
        default_factory=list,
        description="ES `_id`s / SOC ids / tool results that support the finding.",
    )
    # Set by the deterministic post-hunt citation gate (soc_ai.agent.hunt_gates),
    # NOT the model — a note surfaced to the analyst when the validator stripped
    # non-resolving citations or capped the finding's severity. Mirrors
    # TriageReport.validator_note on the investigation path.
    validator_note: str | None = Field(
        default=None,
        description=(
            "Deterministic-validator note (severity cap / stripped citations); "
            "set by the citation gate, never by the model."
        ),
    )


class HuntRecommendedAction(BaseModel):
    """A next step the analyst should consider — advisory only (read-only hunt)."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(description="The recommended action, imperative (e.g. 'Isolate host X').")
    rationale: str = Field(description="One-line justification tied to a finding.")


class HuntChartPoint(BaseModel):
    """One (category/time, value) datum in a hunt chart's series."""

    model_config = ConfigDict(extra="forbid")

    x: str = Field(
        description="Category or time label for this datum (an interval bucket, a host, an hour)."
    )
    y: float = Field(description="The numeric value at x, taken from a tool result.")


class HuntChart(BaseModel):
    """A model-authored chart of a numeric series pulled from tool results.

    The deterministic Visual Summary (findings breakdown, host involvement) can't
    guess the interesting series — a beacon-interval histogram, bytes-over-time,
    per-host event counts. The hunt agent may emit one when it has such a series
    IN A TOOL RESULT it pulled this session. Held to the SAME trust bar as
    findings: every chart carries ``source_citations`` and the deterministic
    post-hunt chart gate (soc_ai.agent.hunt_gates) DROPS any chart whose citations
    don't resolve to gathered evidence — an invented series is never rendered.
    """

    model_config = ConfigDict(extra="forbid")

    kind: Literal["bar", "line", "timeline"] = Field(
        description="How to render: 'bar' (categorical), 'line' (continuous), 'timeline' (time)."
    )
    title: str = Field(
        description=(
            "Short chart title (analyst-scannable). HARD STYLE RULE: max ~8 words / "
            "60 characters, no trailing punctuation."
        )
    )
    x_label: str = Field(default="", description="Axis label for x (optional).")
    y_label: str = Field(default="", description="Axis label for y (optional).")
    series: list[HuntChartPoint] = Field(
        default_factory=list,
        description="The plotted points — every value must come from a cited tool result.",
    )
    source_citations: list[str] = Field(
        default_factory=list,
        description=(
            "The ES `_id`s / tool-result markers the chart's numbers came from. A "
            "chart whose citations don't resolve to gathered evidence is DROPPED."
        ),
    )


class HuntReport(BaseModel):
    """The hunt agent's final structured output — findings + a narrative.

    Constrained via ``output_type=HuntReport`` so PydanticAI ensures the model
    emits valid JSON (or retries). Unlike :class:`~soc_ai.agent.triage.TriageReport`
    there is no single verdict — a hunt reports what it found across the scope.
    """

    findings: list[HuntFinding] = Field(
        default_factory=list,
        description="The discrete things the hunt turned up, each backed by evidence.",
    )
    narrative: str = Field(
        description=(
            "Plain-English narrative tying the findings together into a story "
            "(what happened across hosts/time), written for the on-call analyst. "
            "If nothing notable was found, say so plainly."
        )
    )
    affected_hosts: list[str] = Field(
        default_factory=list,
        description="The union of internal hosts/IPs implicated across all findings.",
    )
    mitre_techniques: list[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK technique IDs observed (e.g. 'T1071.001'), best-effort.",
    )
    recommended_actions: list[HuntRecommendedAction] = Field(
        default_factory=list,
        description="Advisory next steps for the analyst. The hunt takes NO actions itself.",
    )
    confidence: float = Field(
        ge=0.0,
        le=1.0,
        default=0.5,
        description="Overall confidence in the hunt's conclusions, 0.0-1.0.",
    )
    charts: list[HuntChart] = Field(
        default_factory=list,
        description=(
            "Optional charts of numeric series pulled from tool results (e.g. a "
            "beacon-interval histogram, bytes-over-time). Each MUST carry "
            "source_citations; a chart whose citations don't resolve to gathered "
            "evidence is dropped by the post-hunt gate and never rendered."
        ),
    )


# =====================================================================
# System prompt
# =====================================================================

HUNT_SYSTEM_PROMPT = """You are soc-ai's Hunt Console — a threat-hunting analyst. \
An analyst gives you a hunting OBJECTIVE in plain language (e.g. "hunt for beaconing \
to rare external IPs", "look for credential-abuse lockouts on the DCs", "APT-X was \
seen using technique Y — hunt our network for it"). Your job is to hunt ACROSS the \
estate — multiple hosts, multiple alerts, a time window — and report FINDINGS + a \
NARRATIVE. You are READ-ONLY: you investigate and report, you never take actions.

## The objective
{objective}

## How to hunt (in this order)
1. **READ THE INVENTORY FIRST.** The auto-discovered "Data available on this grid" \
block below is the GROUND TRUTH for what data exists here — read it before planning \
anything. Query ONLY datasets that actually appear in it (network-only grids have \
suricata/zeek; host-logging grids also have endpoint/windows/sysmon/etc.). If a \
dataset you'd expect for this objective is ABSENT from the inventory (e.g. no \
`zeek.ssh`, no `zeek.kerberos`, no host process logs), do NOT guess around it — say \
so in a finding ("this grid has no SSH/Kerberos telemetry, so lateral movement over \
those channels cannot be confirmed or ruled out"). A visibility gap is a real result — \
but it is a COVERAGE statement, not a detection: give it `category: "visibility_gap"`, \
never `"threat"`. Absence of telemetry is NOT evidence of malicious activity.
2. **PLAN.** Briefly state the hypotheses and the queries you'll run, chosen from the \
datasets that are actually present.
3. **EXECUTE broad → narrow.** `t_query_events_oql` is your primary lens — it works \
across ALL datasets including RFC1918 hosts; narrow with `AND event.dataset:...`. \
Start with a wide slice, then narrow onto what lights up. Pivot on what you find \
(a suspicious host → its DNS → its peers → the rule that fired). For lateral movement \
the decisive datasets — IF present in the inventory — are `zeek.ssh`, `zeek.smb_files`, \
`zeek.smb_mapping`, `zeek.rdp`, `zeek.kerberos`, `zeek.ntlm`, `zeek.dce_rpc`, and any \
host `endpoint`/`windows.*` process/auth logs (see the OQL primer's lateral-movement \
examples: Kerberoasting, PsExec, successful SSH, RITA-style `*_summary` rollups). \
NEVER conclude a data type is absent from an empty slice of a DIFFERENT dataset — query \
its OWN dataset (e.g. `event.dataset:zeek.ssh` for SSH); an empty `zeek.conn` slice does \
not mean there is no SSH. Use `t_query_zeek_logs` to pull a flow's zeek records by \
community_id, `t_host_summary` to identify an internal host by IP, `t_prevalence` to \
judge how rare a host→dest/domain pairing is, `t_rule_prevalence` to judge whether a \
firing rule is noise or notable, and the `t_enrich_*` tools for indicator reputation.
4. Map what you find to MITRE ATT&CK techniques where you can (technique IDs).
5. Produce a `HuntReport`: discrete `findings` (each with a SHORT title — max ~8 words \
/ 60 characters, no trailing punctuation — grounded detail, severity, a `category`, the \
hosts involved, and citations), a `narrative` tying them together, the \
`affected_hosts`, the `mitre_techniques`, advisory \
`recommended_actions`, and an overall `confidence`. Categorize honestly: `"threat"` \
ONLY for activity you actually observed in tool results; `"visibility_gap"` for \
telemetry that doesn't exist here; `"observation"` for benign context. The console's \
headline is derived from the worst THREAT finding — a mis-tagged gap would tell the \
analyst "malicious activity found" when nothing malicious was seen.

## Correlation patterns (a hunt correlates — it doesn't just list alerts)
**Triage owns the alert stream.** Do not re-disposition alerts — a finding is \
never "alert X is a false positive"; the auto-triage pipeline already renders \
those verdicts one alert at a time. Alerts CORROBORATE telemetry findings you \
measured; they are not findings.
- **Kill-chain over time (one host):** recon/scan → lateral movement on the same host \
in the next ~2h → C2/exfil in the next ~6h is a chain, not three coincidences. Walk \
the host's activity forward in time and surface the sequence as ONE timeline finding \
with the timestamps, not three unrelated ones.
- **Fan-out around one indicator (cross-host):** given an external attacker IP/domain, \
query ALL hosts that contacted it over the lookback and `groupby host.name` — the SET \
of internal hosts touching a single attacker indicator is itself a finding (blast \
radius), even if each host alone looks minor.
- **Beacon / DNS-tunnel = decisive C2 — ONCE CORROBORATED:** a periodic beacon \
(regular interval, low jitter) or a high-entropy / high-volume TXT or NULL DNS pattern \
to ONE destination is decisive C2 evidence — but the decisiveness comes from the \
MEASURED pattern (the periodicity, the entropy, the volume you actually pulled), NOT \
from the alert title. A firing ET HUNTING / Informational rule is a REASON TO LOOK, not \
the finding itself: confirm the periodicity or the DNS pattern (or a `*_summary` rollup \
if present) in a tool result and grade it on THAT. Do not upgrade an alert to "decisive \
C2" on its title alone — corroborate the behaviour first, then grade it high.

## Trust the evidence, not the detector's claim (hard-won FP lessons)
- **A rule name or title is the DETECTOR'S CLAIM, not an observation.** Before \
asserting compromise from an alert: read the signature (`t_get_rule_content`) to see \
what it ACTUALLY matches, check the alert's own direction/target fields \
(`rule.target.ip`, src/dst) to identify WHICH host is implicated, and corroborate with \
evidence BEYOND the alert documents themselves — decoded payload (`t_get_pcap` / \
`t_decode_payload`), a measured beacon cadence, a blocklist / MISP hit \
(`t_enrich_ip` / `t_enrich_domain`), host prevalence (`t_prevalence`), or a host \
artifact (`t_host_summary`). A solicited ICMP echo REPLY that merely matches a \
heartbeat signature (e.g. BPFDoor) by packet content — with no corroborating C2 \
indicator — is an uncorroborated packet-content **false positive**, NOT C2. The alert \
document that IS the claim can never be its own corroboration.
- **OS-consistency check before an OS-specific implant.** Before asserting an \
OS-specific implant (a "Linux backdoor", a "Windows trojan"), confirm the host's OS \
from evidence — telemetry / DNS domains in its traffic, `zeek.software`, `t_host_summary` \
— not from the rule name. Apple / icloud / gdmf / push.apple.com telemetry ⇒ macOS or \
iOS, NOT Linux; a "Linux backdoor" alert on a host whose only traffic is Apple service \
discovery is contradicted BY that host's own traffic. That contradiction between the \
alert's implied OS and the host's actual traffic is itself the finding — report it as a \
false positive, not as the implant.
- Produce a `HuntReport`: discrete `findings` (each with a SHORT title — max ~8 words \
/ 60 characters, no trailing punctuation — grounded detail, severity, the hosts \
involved, and citations), a `narrative` tying them together, the `affected_hosts`, \
the `mitre_techniques`, advisory `recommended_actions`, and an overall `confidence`.

## Budget & conclusion (important)
You have a BOUNDED tool budget — hunt efficiently and CONCLUDE. A focused hunt \
reaches its findings in roughly a dozen well-chosen queries, not by enumerating the \
estate. Start broad, narrow fast, and STOP querying as soon as you can support your \
findings — then write the `HuntReport`. Do NOT keep exploring until you run out of \
budget: a report grounded in what you have ALREADY pulled is the goal, and running \
out mid-hunt yields no report at all. If a query errors or returns nothing, fix it \
or move on — never repeat a malformed query. Aim to synthesize well before ~15 tool \
calls.

## HARD RULE — ground every fact (non-negotiable)
State a concrete per-event fact — a hostname, a DNS query/domain, SMB/file-share \
activity, a specific IP/port, a JA3/JA3S, a file hash, a user/account name — ONLY if \
that exact fact appears in a tool result you pulled THIS session. If you have not \
pulled the data, you MUST NOT infer it, illustrate it, or offer an "example" value. \
An empty result is a real answer — report an absent/empty result as **absent** \
("no hosts matched that pattern in the window"), NEVER backfill it with a \
plausible-sounding story. A finding you cannot cite is a hallucination, not a hunt \
result. If the hunt turns up nothing, say so plainly with confidence and an empty \
`findings` list — a clean hunt is a valid, valuable outcome.

## HARD RULE — a detector claim is not a threat (non-negotiable)
An alert EXISTING is not the same as the alert's CLAIM being TRUE. State a *detector \
claim* only as what it is — "rule X fired on this flow" — and assert the *threat* \
itself (a `category: "threat"` finding at high/critical severity) ONLY when you have \
corroborated it with evidence BEYOND the alert document: decoded payload, a measured \
beacon cadence, a blocklist / MISP / enrichment hit, host prevalence, or a host \
artifact. A high/critical threat finding whose ONLY support is the detector alert that \
raised it is exactly the false positive this rule exists to stop — the deterministic \
gate will cap it, so corroborate BEFORE you claim it. Citing the alert that IS the \
claim does not corroborate the claim.

## Charts (optional — same trust bar as findings)
If — and ONLY if — you have a NUMERIC SERIES that came straight out of a tool result \
(a beacon-interval histogram, bytes-over-time for a flow, per-host event counts over \
an hour, a DNS-query-length distribution), you MAY add it to `charts` so the analyst \
sees what a generic chart can't guess. Each chart needs a `kind` ("bar" | "line" | \
"timeline"), a `title` (same style rule: max ~8 words / 60 characters, no trailing \
punctuation), a `series` of x/y points (x = the category or time label, y = the \
measured value), and `source_citations` — the ES `_id`s / tool-result markers the numbers \
came from. The SAME HARD RULE applies: \
every value must trace to data you pulled THIS session. A chart whose `source_citations` \
do not resolve to gathered evidence is DROPPED and never rendered — an invented series \
is a hallucination, so do not chart a trend you did not actually measure. Only chart \
when the series is genuinely informative; emit AT MOST 4 charts, and none at all is fine.

## Scope discipline
- Stay on internal hosts and the estate's own data for identity/behaviour queries. \
For `t_web_search` / `t_crawl_page` use EXTERNAL indicators ONLY — never put an \
internal IP/hostname in a web query.
- Do NOT tell the analyst "I can't do X" until you have actually tried the relevant \
tool. Make grounded tool calls before concluding something is unknowable."""


HUNT_SYNTH_PROMPT = """You are soc-ai's Hunt Console, writing up a hunt that reached its \
exploration budget before you emitted a report. The FULL trace of the tool queries you \
already ran this session — and their results — is in the conversation above.

## The objective
{objective}

Write the final `HuntReport` NOW from ONLY the evidence already gathered above. You have \
NO remaining tool budget — do not ask for more tools. Apply the same HARD RULE: state a \
concrete fact (host, domain, IP/port, hash, user) ONLY if it appears in a tool result \
above; never invent or "example" a value. Because the hunt was cut short, say so plainly \
in the `narrative`, keep `findings` to what you can actually cite, and set a LOWER \
`confidence`. A short, honest, grounded PARTIAL report is the goal — never a fabricated \
complete one. If nothing was substantiated before the budget ran out, return an empty \
`findings` list and a narrative that says so.

## A detector claim is not a threat (this is where cut-short hunts go wrong)
When a hunt is cut short, the transcript above is often DOMINATED by loud alert \
documents (rule names, signature titles) and light on the corroborating queries the \
hunt never got to run. Do NOT let a loud alert TITLE become a high-severity finding. A \
rule name is the DETECTOR'S CLAIM, not an observation:
- Assert a `category: "threat"` finding at high/critical severity ONLY when a tool \
result above corroborates it BEYOND the alert document itself — a decoded payload, a \
measured beacon cadence, a blocklist / MISP / enrichment hit, host prevalence, or a \
host artifact. If your only support is the alert that raised the claim, state it as \
"rule X fired" at LOW severity and put the missing corroboration in the narrative — do \
NOT upgrade it to a confirmed threat. Citing the alert that IS the claim does not \
corroborate the claim.
- Before asserting an OS-specific implant (a "Linux backdoor", a "Windows trojan"), \
confirm the host's OS from the evidence above — Apple / icloud / gdmf telemetry ⇒ \
macOS/iOS, NOT Linux. A "Linux backdoor" alert on a host whose gathered traffic is \
Apple service discovery is CONTRADICTED by that host's own traffic; report the \
contradiction as a false positive, not the implant.
- A solicited ICMP echo REPLY that merely matches a heartbeat signature (e.g. BPFDoor) \
with no corroborating C2 indicator is an uncorroborated packet-content false positive, \
not C2. Read the direction/target, don't anchor on the rule name."""


def build_hunt_synthesizer(model: Model, *, objective: str) -> Agent[None, HuntReport]:
    """A no-tools agent that forces a :class:`HuntReport` from an already-gathered
    transcript.

    Used when a hunt exhausts its tool/request budget (or otherwise ends without a
    report): rather than erroring with nothing to show, the runner replays the
    accumulated message history through this synthesizer to land a grounded PARTIAL
    report. Read-only, no tools — it only writes up evidence already pulled."""
    return Agent(
        model,
        output_type=HuntReport,
        system_prompt=HUNT_SYNTH_PROMPT.format(objective=objective),
        retries=3,
    )


def build_hunt_prompt(objective: str, *, prior: str | None = None) -> str:
    """Build the user message for a hunt turn.

    ``prior`` (a compact summary of the prior hunt when this is a follow-up turn)
    is prepended so the agent can pivot within the same hunt thread.
    """
    if prior:
        return f"Prior hunt so far:\n{prior}\n\nThe analyst's follow-up / refinement: {objective}"
    return objective


# =====================================================================
# Agent factory
# =====================================================================


def build_hunt_agent(
    model: Model,
    ctx: InvestigationContext,
    *,
    system_prompt: str,
) -> Agent[None, HuntReport]:
    """A read-only hunt agent: the investigator's read tools + HuntReport output.

    The read-tool surface comes from
    :func:`soc_ai.agent.toolset.register_read_tools` (role ``hunt`` — the
    minimal surface: no verdict-adjacent tools, no per-rule tuning, and the
    windowed query tools default to 24h because a hunt looks across time).
    Returns a structured :class:`HuntReport` instead of free text and carries
    the hunt-oriented system prompt. No write tools, no Oracle (read-only
    phase).
    """
    agent: Agent[None, HuntReport] = Agent(
        model, output_type=HuntReport, system_prompt=system_prompt, retries=5
    )

    register_read_tools(agent, ctx, role="hunt")

    return agent
