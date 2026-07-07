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

from typing import Any

from pydantic_ai import Agent
from pydantic_ai.models import Model

from soc_ai.agent.orchestrator import InvestigationContext
from soc_ai.agent.toolset import register_read_tools

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


def build_chat_agent(
    model: Model,
    ctx: InvestigationContext,
    *,
    system_prompt: str,
    proposal_sink: list[dict[str, Any]] | None = None,
) -> Agent[None, str]:
    """A read-only, free-text chat agent with the investigator's read tools.

    The read-tool surface comes from
    :func:`soc_ai.agent.toolset.register_read_tools` (role ``chat``): tools
    gated behind a settings flag (online quartet / PCAP / web search / page
    read) are only registered when enabled, so the model never reaches for a
    disabled tool.

    Pass ``proposal_sink`` (an empty list) to enable the ``propose_verdict`` tool;
    any proposals made during the run will be appended there.
    ``propose_verdict`` is registered HERE (not in the toolset) because it is
    chat-only and owns the ``proposal_sink`` closure.
    """
    agent: Agent[None, str] = Agent(model, output_type=str, system_prompt=system_prompt, retries=3)

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

    register_read_tools(agent, ctx, role="chat")

    return agent
