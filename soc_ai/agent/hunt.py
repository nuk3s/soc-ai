"""Chat-driven threat-hunt agent (Hunt Console).

A Hunt is broader than an Investigation: instead of dispositioning ONE alert
into a verdict, it investigates across multiple alerts / hosts / time — or a
free-form objective the analyst types in plain language ("hunt for beaconing to
rare external IPs", "look for credential-abuse lockouts") — and produces
**findings + a narrative**, mapped to MITRE ATT&CK.

The agent REUSES the investigator's read tools unchanged (OQL, zeek-by-host,
enrichment, prevalence, PCAP facts, web search/crawl). What differs is:

- a **hunt-oriented system prompt** — correlate across hosts/time, map to MITRE,
  report findings + a narrative rather than a single-alert verdict;
- a structured :class:`HuntReport` output schema.

Read-only in this phase — a hunt never acks/escalates/opens a case (no write
tools, no Oracle), exactly like the "Chat about this" agent.
"""

from __future__ import annotations

import logging
from typing import Any

from pydantic import BaseModel, ConfigDict, Field
from pydantic_ai import Agent
from pydantic_ai.models import Model

from soc_ai.agent.orchestrator import InvestigationContext
from soc_ai.tools.crawl_page import crawl_page
from soc_ai.tools.cvedb import cve_lookup
from soc_ai.tools.enrichment import enrich_domain, enrich_hash, enrich_ip
from soc_ai.tools.get_event_raw import get_event_raw
from soc_ai.tools.get_pcap import get_pcap_facts
from soc_ai.tools.greynoise import greynoise
from soc_ai.tools.host_summary import host_summary
from soc_ai.tools.prevalence import prevalence
from soc_ai.tools.query_cases import query_cases
from soc_ai.tools.query_events import query_events_oql
from soc_ai.tools.query_zeek import query_zeek_logs
from soc_ai.tools.rule_prevalence import rule_prevalence
from soc_ai.tools.shodan_host import shodan_host
from soc_ai.tools.shodan_internetdb import shodan_internetdb
from soc_ai.tools.web_search import web_search

_LOGGER = logging.getLogger(__name__)


# =====================================================================
# Output schema
# =====================================================================


class HuntFinding(BaseModel):
    """One discrete thing the hunt turned up, backed by evidence."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(description="Short headline for the finding (analyst-scannable).")
    detail: str = Field(
        description="2-4 sentences: what was observed and why it matters, grounded in tool results."
    )
    severity: str = Field(
        default="info",
        description="One of 'info' | 'low' | 'medium' | 'high' | 'critical'.",
    )
    hosts: list[str] = Field(
        default_factory=list,
        description="Internal hosts/IPs this finding concerns.",
    )
    citations: list[str] = Field(
        default_factory=list,
        description="ES `_id`s / SOC ids / tool results that support the finding.",
    )


class HuntRecommendedAction(BaseModel):
    """A next step the analyst should consider — advisory only (read-only hunt)."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(description="The recommended action, imperative (e.g. 'Isolate host X').")
    rationale: str = Field(description="One-line justification tied to a finding.")


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

## How to hunt
- PLAN, then EXECUTE. Briefly state the hypotheses/queries you'll run, then run them \
with the read tools. Correlate across hosts and time — a hunt is broader than a \
single alert. Pivot on what you find (a suspicious host → its DNS → its peers → the \
rule that fired).
- Use `t_query_events_oql` as your primary lens — it works across ALL datasets \
(suricata, zeek.conn/dns/http/ssl, endpoint), including RFC1918 hosts. Narrow with \
`AND event.dataset:...`. Use `t_query_zeek_logs` to pull a flow's zeek records by \
community_id, `t_host_summary` to identify an internal host by IP, `t_prevalence` to \
judge how rare a host→dest/domain pairing is, `t_rule_prevalence` to judge whether a \
firing rule is noise or notable, and the `t_enrich_*` tools for indicator reputation.
- Map what you find to MITRE ATT&CK techniques where you can (technique IDs).
- Produce a `HuntReport`: discrete `findings` (each with a title, grounded detail, \
severity, the hosts involved, and citations), a `narrative` tying them together, the \
`affected_hosts`, the `mitre_techniques`, advisory `recommended_actions`, and an \
overall `confidence`.

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
`findings` list and a narrative that says so."""


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
        return (
            f"Prior hunt so far:\n{prior}\n\n"
            f"The analyst's follow-up / refinement: {objective}"
        )
    return objective


# =====================================================================
# Agent factory
# =====================================================================


def build_hunt_agent(  # noqa: PLR0915 - tool registrations are inherently long
    model: Model,
    ctx: InvestigationContext,
    *,
    system_prompt: str,
) -> Agent[None, HuntReport]:
    """A read-only hunt agent: the investigator's read tools + HuntReport output.

    Mirrors :func:`soc_ai.agent.chat_agent.build_chat_agent` — same read tools,
    same settings-gated online tools — but returns a structured
    :class:`HuntReport` instead of free text, and carries the hunt-oriented
    system prompt. No write tools, no Oracle (read-only phase).
    """
    agent: Agent[None, HuntReport] = Agent(
        model, output_type=HuntReport, system_prompt=system_prompt, retries=5
    )
    s = ctx.settings

    @agent.tool_plain
    async def t_query_events_oql(
        query: str, time_range_minutes: int = 1440, max_results: int = 25
    ) -> dict[str, Any]:
        """Run a validated OQL query against the SO events index across ALL datasets.

        The default window is wide (24h) because a hunt looks across time; pass a
        larger `time_range_minutes` for a broader sweep. Works on RFC1918 hosts."""
        try:
            result = await query_events_oql(
                query,
                elastic=ctx.elastic,
                settings=s,
                time_range_minutes=time_range_minutes,
                max_results=min(max_results, 25),
                time_anchor=ctx.default_time_anchor,
            )
            return result.model_dump(mode="json")
        except Exception as e:
            return {"error": str(e)}

    @agent.tool_plain
    async def t_query_zeek_logs(
        community_id: str, log_types: list[str] | None = None, time_range_minutes: int = 1440
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Fetch Zeek records sharing a network.community_id (conn/dns/http/ssl/files)."""
        try:
            return await query_zeek_logs(
                community_id,
                elastic=ctx.elastic,
                settings=s,
                log_types=log_types,
                time_range_minutes=time_range_minutes,
                max_results=25,
                time_anchor=ctx.default_time_anchor,
            )
        except Exception as e:
            return {"error": str(e)}

    @agent.tool_plain
    async def t_enrich_ip(ip: str) -> dict[str, Any]:
        """Local IP enrichment (blocklists + MaxMind ASN/Geo + cloud tag + MISP)."""
        try:
            r = await enrich_ip(
                ip,
                settings=s,
                misp=ctx.misp,
                blocklist=ctx.blocklist,
                maxmind=ctx.maxmind,
                cloud=ctx.cloud,
            )
            return r.model_dump(mode="json")
        except Exception as e:
            return {"error": str(e)}

    @agent.tool_plain
    async def t_enrich_domain(domain: str) -> dict[str, Any]:
        """Local domain enrichment (blocklists + optional MISP)."""
        try:
            r = await enrich_domain(domain, settings=s, misp=ctx.misp, blocklist=ctx.blocklist)
            return r.model_dump(mode="json")
        except Exception as e:
            return {"error": str(e)}

    @agent.tool_plain
    async def t_enrich_hash(hash_value: str, algo: str = "sha256") -> dict[str, Any]:
        """Local file-hash enrichment (blocklists + optional MISP)."""
        try:
            r = await enrich_hash(
                hash_value, algo=algo, settings=s, misp=ctx.misp, blocklist=ctx.blocklist
            )
            return r.model_dump(mode="json")
        except Exception as e:
            return {"error": str(e)}

    @agent.tool_plain
    async def t_query_cases(
        query: str, status: str | None = None
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Search SOC cases by free text + optional status."""
        try:
            cases = await query_cases(
                query, elastic=ctx.elastic, settings=s, status=status, max_results=10
            )
            return [c.model_dump(mode="json") for c in cases]
        except Exception as e:
            return {"error": str(e)}

    @agent.tool_plain
    async def t_get_event_raw(event_id: str) -> dict[str, Any]:
        """Fetch a single event's full raw _source by ES _id (deep-dive one event)."""
        try:
            return await get_event_raw(event_id, elastic=ctx.elastic, settings=s)
        except Exception as e:
            return {"error": str(e)}

    @agent.tool_plain
    async def t_host_summary(ip: str, lookback_hours: int = 24) -> dict[str, Any]:
        """Identify an internal host by IP: hostname, device/OS, role, peers, DNS."""
        try:
            return await host_summary(
                ip,
                elastic=ctx.elastic,
                settings=s,
                lookback_hours=lookback_hours,
                time_anchor=ctx.default_time_anchor,
            )
        except Exception as e:
            return {"error": str(e)}

    @agent.tool_plain
    async def t_prevalence(
        ip: str,
        peer_ip: str | None = None,
        domain: str | None = None,
        lookback_days: int = 90,
    ) -> dict[str, Any]:
        """Has THIS host talked to THIS dest/domain before, and how rare is it?

        Learned from the events index only (no external calls). Returns first/last
        seen, distinct-day count, an `is_novel` flag and a `rarity` label."""
        try:
            return await prevalence(
                ip,
                elastic=ctx.elastic,
                settings=s,
                peer_ip=peer_ip,
                domain=domain,
                lookback_days=lookback_days,
                time_anchor=ctx.default_time_anchor,
            )
        except Exception as e:
            return {"error": str(e)}

    @agent.tool_plain
    async def t_rule_prevalence(rule_name: str, lookback_days: int = 30) -> dict[str, Any]:
        """Base-rate / noisiness of a Suricata detection rule across the estate."""
        try:
            return await rule_prevalence(
                rule_name,
                elastic=ctx.elastic,
                settings=s,
                lookback_days=lookback_days,
            )
        except Exception as e:
            return {"error": str(e)}

    @agent.tool_plain
    async def t_shodan_internetdb(ip: str) -> dict[str, Any]:
        """External-asset view of a PUBLIC IP from Shodan InternetDB (free, no key)."""
        try:
            return await shodan_internetdb(ip, settings=s)
        except Exception as e:
            return {"error": str(e)}

    @agent.tool_plain
    async def t_greynoise(ip: str) -> dict[str, Any]:
        """GreyNoise lookup for an EXTERNAL IP — scanner/benign/classification."""
        try:
            return await greynoise(ip, settings=s)
        except Exception as e:
            return {"error": str(e)}

    @agent.tool_plain
    async def t_shodan_host(ip: str) -> dict[str, Any]:
        """FULL Shodan host lookup for a PUBLIC IP (needs the operator's API key)."""
        try:
            return await shodan_host(ip, settings=s)
        except Exception as e:
            return {"error": str(e)}

    @agent.tool_plain
    async def t_cve_lookup(cve_id: str) -> dict[str, Any]:
        """Score a named CVE via Shodan CVEDB (free, no key): CVSS/EPSS/KEV."""
        try:
            return await cve_lookup(cve_id, settings=s)
        except Exception as e:
            return {"error": str(e)}

    if s.pcap_enabled:

        @agent.tool_plain
        async def t_get_pcap(
            src_ip: str | None = None, dst_ip: str | None = None
        ) -> dict[str, Any]:
            """Real packet facts for a flow (five-tuples, SNI/DNS/HTTP, beacon CV)."""
            try:
                r = await get_pcap_facts(
                    settings=s, src_ip=src_ip, dst_ip=dst_ip, alert_ts=ctx.default_time_anchor
                )
                return r.model_dump(mode="json") if hasattr(r, "model_dump") else r
            except Exception as e:
                return {"error": str(e)}

    if s.web_search_enabled:

        @agent.tool_plain
        async def t_web_search(query: str) -> dict[str, Any]:
            """Web search for EXTERNAL-indicator reputation (SearXNG). External only."""
            try:
                return await web_search(query, settings=s)
            except Exception as e:
                return {"error": str(e)}

    if s.crawl4ai_enabled:

        @agent.tool_plain
        async def t_crawl_page(url: str) -> dict[str, Any]:
            """Deep-read an EXTERNAL page to markdown (crawl4ai). External only."""
            try:
                return await crawl_page(url, settings=s)
            except Exception as e:
                return {"error": str(e)}

    return agent
