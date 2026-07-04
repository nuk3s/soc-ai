"""Read-only conversational agent for "Chat about this" follow-ups.

After a hunt lands a verdict, the analyst can interrogate it in natural language.
This agent is seeded with the investigation's verdict + rationale + a summary of
the alert, and given the same READ tools the investigator uses (query events/zeek,
enrich indicators, fetch PCAP facts, web search/crawl) — but NO write tools and
NO Oracle. It answers in free text (``output_type=str``).

v1 scope: read-only. Acks/escalations stay on the main
investigation's Approve/Reject gate.
"""

from __future__ import annotations

import logging
from typing import Any

from pydantic_ai import Agent
from pydantic_ai.models import Model

from soc_ai.agent.orchestrator import InvestigationContext
from soc_ai.tools.crawl_page import crawl_page
from soc_ai.tools.cvedb import cve_lookup
from soc_ai.tools.discover import describe_dataset, field_values
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
from soc_ai.tools.rule_tuning import suggest_rule_tuning
from soc_ai.tools.shodan_host import shodan_host
from soc_ai.tools.shodan_internetdb import shodan_internetdb
from soc_ai.tools.web_search import web_search

_LOGGER = logging.getLogger(__name__)

CHAT_SYSTEM_PROMPT = """You are soc-ai's investigation assistant. You answer an \
analyst's follow-up questions about ONE specific alert investigation that has \
ALREADY been completed. You are READ-ONLY — you investigate and explain, you do \
not take actions.

## The investigation under discussion
{context}

## How to answer
- Structure every reply for fast scanning (it is rendered as Markdown):
  1. **A one-line bottom line in bold** — the direct answer to what they asked.
  2. A short bulleted list of the supporting evidence (ids, fields, tool results).
  3. Only if needed, one closing line of caveat or next step.
  Keep it tight — no walls of prose; if a single bold line fully answers, stop there.
- When the question needs data you don't already have, CALL A READ TOOL rather \
than guessing: query events/Zeek, enrich an IP/domain/hash, pull PCAP facts, or \
web-search an EXTERNAL indicator. An empty result is still an answer — report an \
absent or empty result as **absent** ("no DNS records came back for that host"), \
NEVER backfill it with a plausible-sounding story.
- Stay scoped to this alert and its host(s). For web_search / crawl_page use \
EXTERNAL indicators ONLY — never put an internal IP/hostname in a web query.
- Cite what you found (an id, a field, a tool result). If you genuinely can't \
determine something, say so.

## HARD RULE — never invent per-event facts (this is non-negotiable)
You may state a concrete per-event fact — a hostname (e.g. `DESKTOP-…`/an FQDN), a \
DNS query or domain, SMB / file-share activity, a specific IP or port, a JA3/JA3S, a \
file hash, a user/account name — ONLY if that exact fact appears in:
  (a) a tool result you pulled THIS turn, or
  (b) the seeded investigation context above (the alert / verdict / rationale / summary).
If you have not pulled the data, you MUST NOT infer it, illustrate it, or offer an \
"example" value. Say so plainly and CALL THE APPROPRIATE TOOL — e.g. "I haven't \
pulled this host's DNS yet — let me check" then run `t_query_events_oql` with \
`event.dataset:zeek.dns AND ...`. A hostname you did not read, a domain you did not \
observe, and a file-share you did not query are HALLUCINATIONS, not answers, even if \
they sound right for the host's role. When in doubt, pull it or name it as unknown.
- You may PROPOSE a new verdict by calling `propose_verdict` once you have gathered \
grounded evidence (cite the tools/ids you pulled). You do NOT apply it — the analyst \
reviews your proposal and applies it. Only propose 'true_positive' or 'false_positive'; \
if you still can't decide, keep investigating and say what is missing.

## Investigating internal hosts and pulling more evidence

**Characterising a host by IP** — OQL works across ALL datasets, including RFC1918 \
addresses. Run `t_query_events_oql` with `source.ip:<IP> OR destination.ip:<IP>` to \
find every event touching that host. Narrow with `AND event.dataset:zeek.conn` (or \
`zeek.dns`, `zeek.http`, `zeek.ssl`, `suricata`) to focus on one log type.

**Getting the hostname** — `host.name` is present on most zeek.conn and endpoint \
events. A targeted query such as \
`event.dataset:zeek.conn AND (source.ip:<IP> OR destination.ip:<IP>)` will surface it.

**Inferring host role from DNS** — query \
`event.dataset:zeek.dns AND (source.ip:<IP> OR destination.ip:<IP>)` to see what \
domains the host resolved; the lookup patterns reveal whether it is a gateway, a \
workstation, a server, etc.

**Using `t_enrich_ip` on internal IPs** — enrichment on an RFC1918 address returns \
`internal=true`, which is a real and useful signal (confirms the IP is a trusted \
internal endpoint, not an external threat actor). It also runs blocklist checks. Do \
NOT dismiss `t_enrich_ip` as useless for internal IPs — interpret `internal=true` \
correctly: this is not an external threat. For host *identity* use OQL/Zeek queries \
instead.

**Pulling a single event's full fields** — use `t_get_event_raw(event_id)` when a \
pivot summary omitted a field you need (raw payload bytes, all zeek fields, full \
suricata metadata). Pass the `_id` of any event already seen in the investigation.

**Behaviour rule** — Do NOT tell the analyst "I can't do X" until you have actually \
tried the relevant tool. Make 1-3 grounded tool calls before concluding something is \
unknowable. If after trying the data is genuinely absent, say what you queried and \
what came back empty."""


def build_chat_context_block(
    *,
    alert_summary: str,
    verdict: str | None,
    confidence: float | None,
    rationale: str | None,
    summary: str | None,
) -> str:
    """Render the per-investigation seed block embedded in the system prompt."""
    lines = [f"Alert: {alert_summary}"]
    if verdict:
        conf = f" (confidence {confidence:.2f})" if confidence is not None else ""
        lines.append(f"Verdict reached: {verdict}{conf}")
    if rationale:
        lines.append(f"Why: {rationale}")
    if summary:
        lines.append(f"Analyst summary: {summary}")
    return "\n".join(lines)


def build_chat_agent(  # noqa: PLR0915
    model: Model,
    ctx: InvestigationContext,
    *,
    system_prompt: str,
    proposal_sink: list[dict[str, Any]] | None = None,
) -> Agent[None, str]:
    """A read-only, free-text chat agent with the investigator's read tools.

    Tools gated behind a settings flag (PCAP / web search / page read) are only
    registered when enabled, so the model never reaches for a disabled tool.

    Pass ``proposal_sink`` (an empty list) to enable the ``propose_verdict`` tool;
    any proposals made during the run will be appended there.
    """
    agent: Agent[None, str] = Agent(model, output_type=str, system_prompt=system_prompt, retries=3)
    s = ctx.settings

    if proposal_sink is not None:

        @agent.tool_plain
        async def propose_verdict(
            verdict: str,
            confidence: float,
            rationale: str,
            citations: list[str],
            recommended_actions: list[dict[str, Any]] | None = None,
        ) -> str:
            """Propose a new verdict for this alert once you have grounded evidence.

            Use ONLY 'true_positive' or 'false_positive'. Cite the tools/ids your
            investigation pulled. This does NOT change the verdict — it surfaces an
            'Apply' control for the analyst, who makes the final call.
            """
            proposal_sink.append(
                {
                    "verdict": verdict,
                    "confidence": confidence,
                    "rationale": rationale,
                    "citations": list(citations or []),
                    "recommended_actions": list(recommended_actions or []),
                }
            )
            return (
                "Proposal recorded. The analyst will see an Apply control if it is evidence-backed."
            )

    @agent.tool_plain
    async def t_query_events_oql(
        query: str, time_range_minutes: int = 60, max_results: int = 25
    ) -> dict[str, Any]:
        """Run a validated OQL query against the SO events index. The window is
        centered on the alert's @timestamp automatically."""
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
        community_id: str, log_types: list[str] | None = None, time_range_minutes: int = 60
    ) -> list[dict[str, Any]] | dict[str, Any]:
        """Fetch Zeek records sharing a network.community_id (conn/dns/http/ssl/files/ssh)."""
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
    async def t_describe_dataset(dataset: str) -> dict[str, Any]:
        """Discover the fields POPULATED on a dataset (e.g. `zeek.ssh`, `endpoint`,
        `windows.security`) by sampling recent docs — field names + example values +
        coverage. Works for network AND host datasets."""
        return await describe_dataset(dataset, elastic=ctx.elastic, settings=s)

    @agent.tool_plain
    async def t_field_values(
        field: str, dataset: str | None = None, size: int = 25
    ) -> dict[str, Any]:
        """List the top VALUES a field takes (terms aggregation), optionally within one
        dataset — e.g. what `rule.name`s fire or what `event.dataset`s are present."""
        return await field_values(
            field, elastic=ctx.elastic, settings=s, dataset=dataset, size=size
        )

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
        """Fetch a single event's full raw _source by ES _id.

        Use when a pivot summary omitted a field you need (e.g. raw payload
        bytes, all zeek fields, full suricata metadata).  For host
        characterisation prefer t_query_events_oql; use this for
        single-event deep-dives.
        """
        try:
            return await get_event_raw(event_id, elastic=ctx.elastic, settings=s)
        except Exception as e:
            return {"error": str(e)}

    @agent.tool_plain
    async def t_host_summary(ip: str, lookback_hours: int = 24) -> dict[str, Any]:
        """Identify an internal host by IP: hostname, device/OS, role, peers, DNS.

        Use this FIRST whenever the question is about *what a host is* (its
        device type, OS, or hostname) — it parses the host's HTTP User-Agents so
        an iPhone is reported as an iPhone, not a Mac. Returns the evidence
        string behind each guess. Prefer it over inferring identity from a label
        or a partial UA you saw in passing.
        """
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

        Learned from the events index only (no external calls). Pass `peer_ip`
        to scope to a host pair, `domain` to scope to a domain (DNS/SNI/HTTP),
        or neither to summarize the host's overall activity. Returns first/last
        seen, distinct-day count, an `is_novel` flag and a `rarity` label
        ('first-seen' | 'rare' | 'common')."""
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
        """Base-rate / noisiness of a Suricata detection rule across the estate.

        Answers "is this rule NOISY (fires constantly across many hosts -> a
        firing is likely benign HERE and weak evidence) or RARE / FIRST-SEEN (a
        firing is notable)?". Call this whenever the question leans on a rule
        label — before trusting the signature name, check whether that signature
        is a constant-firing nuisance on this grid. Returns total_fires, distinct
        src/dest hosts, first/last seen, fires_per_day, and a noisiness bucket.
        """
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
    async def t_suggest_rule_tuning(rule_name: str, lookback_days: int = 7) -> dict[str, Any]:
        """Detection tuning: is this Suricata rule a noisy FP nuisance to mute?

        Answers "is this rule mostly-benign noise that should be muted/re-tuned,
        or is it pulling its weight?". Returns the rule's alert volume, its
        acknowledged-vs-escalated disposition trend (the ES proxy for FP vs TP),
        and a mute/monitor/none recommendation with a one-line reason. READ-ONLY —
        it nominates, it does not change Security Onion.
        """
        try:
            return await suggest_rule_tuning(
                rule_name,
                elastic=ctx.elastic,
                settings=s,
                lookback_days=lookback_days,
            )
        except Exception as e:
            return {"error": str(e)}

    # The four ONLINE-enrichment tools (GreyNoise / Shodan InternetDB / full
    # Shodan / CVEDB) are only registered when the master egress toggle is on;
    # otherwise every call would just return "skipped (online enrichment off)"
    # and burn a tool call. InternetDB + CVEDB are keyless but still egress,
    # so they sit behind the same toggle.
    if s.allow_online_enrichment:

        @agent.tool_plain
        async def t_shodan_internetdb(ip: str) -> dict[str, Any]:
            """External-asset view of a PUBLIC IP from Shodan InternetDB (free, no key).

            Returns the open ports, software CPEs, reverse-DNS hostnames, tags
            (cdn/cloud/self-signed) and known CVEs Shodan last observed on that
            address — use it to corroborate "what is this external host?" for an
            alert against an unknown public IP. ONLINE tool; private/reserved IPs
            are skipped (never sent off-box).
            """
            try:
                return await shodan_internetdb(ip, settings=s)
            except Exception as e:
                return {"error": str(e)}

        @agent.tool_plain
        async def t_greynoise(ip: str) -> dict[str, Any]:
            """GreyNoise lookup for an EXTERNAL IP — is it indiscriminately scanning
            the internet (noise), a known-benign service (riot), and its
            classification. EXTERNAL IPs only; internal IPs are skipped. ONLINE
            tool: returns a clean not-configured dict (no network I/O) when the
            API key is unset."""
            try:
                return await greynoise(ip, settings=s)
            except Exception as e:
                return {"error": str(e)}

        @agent.tool_plain
        async def t_shodan_host(ip: str) -> dict[str, Any]:
            """FULL Shodan host lookup for a PUBLIC IP (needs the operator's API
            key): network owner (org/isp/asn), geo, guessed OS, open ports, the
            per-service banners (product/version), and known CVEs — deeper than
            t_shodan_internetdb. ONLINE tool: returns a clean not-configured dict
            (no network I/O) when SHODAN_API_KEY is unset; private/internal IPs
            are skipped."""
            try:
                return await shodan_host(ip, settings=s)
            except Exception as e:
                return {"error": str(e)}

        @agent.tool_plain
        async def t_cve_lookup(cve_id: str) -> dict[str, Any]:
            """Score a named CVE via Shodan CVEDB (free, no key): CVSS base score,
            EPSS exploit-probability + ranking, CISA KEV (actively-exploited) flag,
            summary and references — use to judge HOW SEVERE / HOW LIKELY-EXPLOITED
            a CVE is. ONLINE tool."""
            try:
                return await cve_lookup(cve_id, settings=s)
            except Exception as e:
                return {"error": str(e)}

    if s.pcap_enabled:

        @agent.tool_plain
        async def t_get_pcap(
            src_ip: str | None = None, dst_ip: str | None = None
        ) -> dict[str, Any]:
            """Real packet facts for a flow (five-tuples, SNI/DNS/HTTP, beacon CV).
            Pass BOTH alert IPs (the BPF is bidirectional)."""
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
