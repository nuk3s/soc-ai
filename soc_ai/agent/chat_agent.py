"""Read-only conversational agents: the per-investigation chat and the general chat.

Both answer an analyst in one turn with the investigator's READ tools (query
events/zeek, enrich indicators, fetch PCAP facts, web search/crawl) — no write
tools, no Oracle, free text (``output_type=str``).

They differ only in what they are ANCHORED to, and in what they may propose:

* :data:`CHAT_SYSTEM_PROMPT` — "Chat about this": ONE completed alert
  investigation, seeded with its verdict + rationale + alert summary; may
  ``propose_verdict``.
* :data:`GENERAL_CHAT_SYSTEM_PROMPT` — the Dashboard's general chat: no alert at
  all, seeded with THE GRID (:func:`build_general_context_block`); may
  ``propose_hunt``.

The trust rules are SHARED TEXT, not a copy (``_HARD_RULE_NEVER_INVENT``,
``_EXTERNAL_INDICATOR_RULE``, ``_ANSWER_SHAPE``, ``_BEHAVIOUR_RULE``): the hunt
console forked this prompt once and quietly missed every fix the chat prompt
received afterwards. A rule fixed here is fixed on both surfaces.

v1 scope: read-only. Acks/escalations stay on the main investigation's
Approve/Reject gate, and a hunt is only ever PROPOSED — the analyst starts it.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from pydantic_ai import Agent
from pydantic_ai.models import Model

from soc_ai.agent.orchestrator import InvestigationContext
from soc_ai.agent.prompts import HOST_NAMING_RULE
from soc_ai.agent.toolset import register_read_tools
from soc_ai.oracle.identifiers import EffectiveIdentifiers

# ── Shared prompt blocks ────────────────────────────────────────────────────
# Every block below is a rule this project paid for in a live failure. They are
# defined once and composed into BOTH prompts; do not inline a second copy.

# The answer contract. Analysts scan; a wall of prose is an unread answer.
# The second bullet is the anti-rationalisation rule: pull it, or report it
# absent — never narrate around a gap.
_ANSWER_SHAPE = """## How to answer
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
"""

# The egress rule. web_search/crawl_page leave the building; an internal host
# name in a public query is a disclosure, not a lookup.
_EXTERNAL_INDICATOR_RULE = (
    "For web_search / crawl_page use EXTERNAL indicators ONLY — never put an "
    "internal IP/hostname in a web query."
)

_CITE_RULE = """- Cite what you found (an id, a field, a tool result). If you genuinely can't \
determine something, say so.
"""

# The canonical hallucination: a zero-tool turn that asserts a hostname, a DNS
# lookup and an SMB share, none of which was ever read. Stated as an absolute
# because a hedged version of this rule does not hold under pressure.
_HARD_RULE_NEVER_INVENT = """
## HARD RULE — never invent per-event facts (this is non-negotiable)
You may state a concrete per-event fact — a hostname (e.g. `DESKTOP-…`/an FQDN), a \
DNS query or domain, SMB / file-share activity, a specific IP or port, a JA3/JA3S, a \
file hash, a user/account name — ONLY if that exact fact appears in:
  (a) a tool result you pulled THIS turn, or
  (b) the seeded {seed_name} above ({seed_parts}).
If you have not pulled the data, you MUST NOT infer it, illustrate it, or offer an \
"example" value. Say so plainly and CALL THE APPROPRIATE TOOL — e.g. "I haven't \
pulled this host's DNS yet — let me check" then run `t_query_events_oql` with \
`event.dataset:zeek.dns AND ...`. A hostname you did not read, a domain you did not \
observe, and a file-share you did not query are HALLUCINATIONS, not answers, even if \
they sound right for the host's role. When in doubt, pull it or name it as unknown.
"""

# Generic host-investigation craft: it is about internal hosts, not about one
# alert, so both surfaces get it. Without it the model treats OQL as
# alert-only and writes off RFC1918 enrichment as useless.
_INTERNAL_HOST_PLAYBOOK = """
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
"""

_EVENT_RAW_PARAGRAPH = """
**Pulling a single event's full fields** — use `t_get_event_raw(event_id)` when a \
pivot summary omitted a field you need (raw payload bytes, all zeek fields, full \
suricata metadata). Pass the `_id` of any event already seen in the {seen_where}.
"""

# "I can't check that" from an agent that never called a tool is the most
# common way a capable assistant looks incapable.
_BEHAVIOUR_RULE = """
**Behaviour rule** — Do NOT tell the analyst "I can't do X" until you have actually \
tried the relevant tool. Make 1-3 grounded tool calls before concluding something is \
unknowable. If after trying the data is genuinely absent, say what you queried and \
what came back empty."""

# When a surface may propose a hunt. Shared text with one ``{answerable}`` slot
# (the examples differ per surface; the discipline must not): the general chat
# had this inline, and the host chat repeating it by hand is how the next fix
# lands on one surface only.
_HUNT_PROPOSAL_RULE = """
## When to answer, and when to propose a hunt
Answer directly. Almost every question asked here — {answerable} — is \
answerable NOW with the read tools, and an answer beats a report.

PROPOSE a hunt by calling `propose_hunt` ONLY when answering genuinely needs a \
SWEEP: many hosts, or a long time window, or a correlation pass that a handful of \
queries in this turn cannot cover. Do it at most once per reply, and only after you \
have looked — say what you already found, then propose the sweep that would settle \
the rest. Write the objective yourself, sharpened by what you just saw (name the \
datasets, hosts and window); do not echo the analyst's sentence back. You do NOT \
start it — the analyst reviews your objective and confirms it. Reaching for a hunt \
because a question looks big is a WORSE answer, not a safer one: a hunt is a \
multi-minute background job.
"""


# ── The per-investigation chat ("Chat about this") ──────────────────────────

CHAT_SYSTEM_PROMPT = (
    """You are soc-ai's investigation assistant. You answer an \
analyst's follow-up questions about ONE specific alert investigation that has \
ALREADY been completed. You are READ-ONLY — you investigate and explain, you do \
not take actions.

## The investigation under discussion
{context}

"""
    + _ANSWER_SHAPE
    + f"- Stay scoped to this alert and its host(s). {_EXTERNAL_INDICATOR_RULE}\n"
    + _CITE_RULE
    + _HARD_RULE_NEVER_INVENT.format(
        seed_name="investigation context",
        seed_parts="the alert / verdict / rationale / summary",
    )
    + """- You may PROPOSE a new verdict by calling `propose_verdict` once you have gathered \
grounded evidence (cite the tools/ids you pulled). You do NOT apply it — the analyst \
reviews your proposal and applies it. Only propose 'true_positive' or 'false_positive'; \
if you still can't decide, keep investigating and say what is missing.
"""
    + _INTERNAL_HOST_PLAYBOOK
    + _EVENT_RAW_PARAGRAPH.format(seen_where="investigation")
    # Shared with both synthesizers (soc_ai.agent.prompts) rather than restated:
    # the seeded context now carries the alert's hosts as identity, and this is
    # what turns that into "pve01 (hypervisor, …)" in the answer.
    + HOST_NAMING_RULE
    + _BEHAVIOUR_RULE
)


# ── The Dashboard's general chat ────────────────────────────────────────────

GENERAL_CHAT_SYSTEM_PROMPT = (
    """You are soc-ai's SOC assistant, answering an analyst at the dashboard of \
THIS Security Onion deployment. There is no single alert under discussion: the \
questions are about the grid itself — what data it collects, what its hosts are \
doing, which rules are noisy, what last night looked like. You are READ-ONLY — \
you investigate and explain, you do not take actions.

## What is already known about this grid
{context}

Everything above is established fact you may cite directly. ANYTHING ELSE about \
this network you must pull with a tool before you say it.

"""
    + _ANSWER_SHAPE
    # The unbounded question space is exactly why this rule matters MORE here:
    # nothing scopes the conversation to one alert's hosts, so an analyst
    # question naming an internal box is one careless call away from a public
    # search engine.
    + f"- {_EXTERNAL_INDICATOR_RULE} The question space here is unbounded and nothing \
scopes it for you — an internal host, subnet or username is an INTERNAL indicator no \
matter how the question was phrased; research only the external side of it.\n"
    + _CITE_RULE
    + _HARD_RULE_NEVER_INVENT.format(
        seed_name="grid context",
        seed_parts="the internal identifiers / dataset inventory / recent posture",
    )
    + _HUNT_PROPOSAL_RULE.format(
        answerable=(
            "what datasets exist, what a host is, whether a rule is noisy, what happened overnight"
        )
    )
    + _INTERNAL_HOST_PLAYBOOK
    + _EVENT_RAW_PARAGRAPH.format(seen_where="conversation or a tool result")
    + HOST_NAMING_RULE
    + _BEHAVIOUR_RULE
)


# ── The host page chat ("Chat about this host") ─────────────────────────────

HOST_CHAT_SYSTEM_PROMPT = (
    """You are soc-ai's SOC assistant, answering an analyst on the page of ONE \
host of THIS Security Onion deployment. Every question is about that host unless \
the analyst clearly says otherwise. You are READ-ONLY — you investigate and \
explain, you do not take actions.

## The host under discussion
{context}

Everything above is established fact you may cite directly. ANYTHING ELSE about \
this host you must pull with a tool before you say it.

"""
    + _ANSWER_SHAPE
    + f"- Stay scoped to this host and its traffic. {_EXTERNAL_INDICATOR_RULE}\n"
    + _CITE_RULE
    + _HARD_RULE_NEVER_INVENT.format(
        seed_name="host context",
        seed_parts="the host line and its dossier",
    )
    + _HUNT_PROPOSAL_RULE.format(
        answerable=(
            "what this host is, who it talks to, what it resolved, whether it answered on a port"
        )
    )
    + _INTERNAL_HOST_PLAYBOOK
    + _EVENT_RAW_PARAGRAPH.format(seen_where="conversation or a tool result")
    + HOST_NAMING_RULE
    + _BEHAVIOUR_RULE
)


# ── Seed context blocks ─────────────────────────────────────────────────────

# Bounds on the general seed block. The grid is the anchor, but it is also
# ambient: a 200-rule / 60-CIDR network must not spend the turn's context on its
# own preamble before the analyst's question is read.
_MAX_IDENTIFIERS_PER_KIND = 8
_MAX_TOP_RULES = 5
_MAX_RULE_NAME_CHARS = 80

# Verdict buckets in the order an analyst reads them; anything else the store
# hands back is appended after, sorted, rather than dropped.
_VERDICT_ORDER = ("true_positive", "false_positive", "needs_more_info")


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


def build_host_context_block(*, ip: str) -> str:
    """Render the host chat's anchor line: WHICH machine this thread is about.

    One sentence, deliberately: the identity itself (hostname, role, policy)
    arrives from :func:`soc_ai.dossier.prompt.host_dossier_prompt_block`, which
    the manager appends — restating it here would be the second answer to "what
    is this host" that the dossier module exists to prevent. The line also puts
    the address itself into ``seed_context``, the corpus the grounding gate
    grades against, so an answer naming the host it was asked about is grounded
    by construction.
    """
    return (
        f"Host page: `{ip}` — the analyst opened this chat from this host's page, "
        "so questions are about this host unless they clearly name another."
    )


def _capped(values: Sequence[str], *, cap: int = _MAX_IDENTIFIERS_PER_KIND) -> str:
    shown = ", ".join(f"`{v}`" for v in values[:cap])
    extra = len(values) - cap
    return f"{shown} (+{extra} more)" if extra > 0 else shown


def _identifier_lines(identifiers: EffectiveIdentifiers | None) -> list[str]:
    """The network's own names. Two jobs, both load-bearing.

    It tells the agent which addresses are OURS (so it stops sending internal
    hosts to web_search and stops reading RFC1918 peers as threat actors), and —
    because the seed block is the corpus ``check_narrative_grounding`` grades
    against — it is what makes a correct answer like "your internal range is
    192.168.10.0/24" come back GROUNDED instead of wearing an ⚠ Unverified
    caveat.
    """
    if identifiers is None:
        return [
            "Internal identifiers: not resolved for this session — treat RFC1918 "
            "addresses as internal and confirm with `t_enrich_ip`."
        ]
    lines: list[str] = []
    if identifiers.cidrs:
        lines.append(f"Internal IP ranges: {_capped([str(c) for c in identifiers.cidrs])}")
    if identifiers.suffixes:
        lines.append(f"Internal DNS suffixes: {_capped(list(identifiers.suffixes))}")
    if identifiers.hosts:
        lines.append(f"Internal hostnames: {_capped(list(identifiers.hosts))}")
    if not lines:
        lines.append(
            "Internal identifiers: none configured — treat RFC1918 addresses as "
            "internal and confirm with `t_enrich_ip`."
        )
    return lines


def _posture_lines(
    verdict_counts: Mapping[str, int] | None,
    top_rules: Sequence[tuple[str, int]] | None,
    window_hours: int,
) -> list[str]:
    """Recent posture: what soc-ai decided lately, and what is making the noise."""
    lines = [f"### Recent posture (last {window_hours}h)"]
    counts = {k: int(v) for k, v in (verdict_counts or {}).items() if int(v) > 0}
    if counts:
        ordered = [k for k in _VERDICT_ORDER if k in counts]
        ordered += sorted(k for k in counts if k not in _VERDICT_ORDER)
        detail = ", ".join(f"{counts[k]} {k}" for k in ordered)
        lines.append(f"Investigations completed: {sum(counts.values())} — {detail}")
    else:
        lines.append(f"Investigations completed: none in the last {window_hours}h.")
    if top_rules:
        shown = "; ".join(
            f"`{name[:_MAX_RULE_NAME_CHARS]}` ({count})"
            for name, count in list(top_rules)[:_MAX_TOP_RULES]
        )
        lines.append(f"Busiest alert rules by volume: {shown}")
    else:
        lines.append("Busiest alert rules by volume: not available — query them if asked.")
    return lines


def build_general_context_block(
    *,
    identifiers: EffectiveIdentifiers | None = None,
    inventory_block: str = "",
    verdict_counts: Mapping[str, int] | None = None,
    top_rules: Sequence[tuple[str, int]] | None = None,
    window_hours: int = 24,
) -> str:
    """Render the general chat's seed block: THE GRID, in place of one alert.

    The investigation chat anchors on an alert plus its stored verdict. A chat
    opened from the dashboard has neither, so its anchor is the deployment:
    whose addresses are internal (``identifiers``, from
    :func:`soc_ai.oracle.identifiers.effective_internal_identifiers`), what
    telemetry exists (``inventory_block``, the already-rendered discovery block
    from :func:`soc_ai.so_client.inventory.format_inventory_block`), and what
    has been happening (``verdict_counts`` / ``top_rules``).

    Every argument is optional and every absence is rendered as a stated
    unknown: a grid whose Elasticsearch is down still gets a usable chat, and
    the model is told what it does NOT know rather than being left to guess.

    This text is prepended to EVERY turn, so what it renders is capped (the
    ``_MAX_*`` constants). ``inventory_block`` is the one part passed through
    whole: it is already bounded by the discovery aggregation, and "what data
    do I have?" is the canonical question this chat exists to answer — an
    inventory clipped here would answer it wrongly, with confidence.
    """
    lines = ["### This grid"]
    lines.extend(_identifier_lines(identifiers))
    lines.append("")
    inventory = (inventory_block or "").strip()
    lines.append(
        inventory
        if inventory
        else "Dataset inventory: unavailable right now — discover it with "
        "`t_field_values` on `event.dataset` before concluding a data type is absent."
    )
    lines.append("")
    lines.extend(_posture_lines(verdict_counts, top_rules, window_hours))
    return "\n".join(lines)


# ── Agent construction ──────────────────────────────────────────────────────


def build_chat_agent(
    model: Model,
    ctx: InvestigationContext,
    *,
    system_prompt: str,
    proposal_sink: list[dict[str, Any]] | None = None,
    hunt_sink: list[dict[str, Any]] | None = None,
    default_window: int | None = None,
) -> Agent[None, str]:
    """A read-only, free-text chat agent with the investigator's read tools.

    The read-tool surface comes from
    :func:`soc_ai.agent.toolset.register_read_tools` (role ``chat``): tools
    gated behind a settings flag (online quartet / PCAP / web search / page
    read) are only registered when enabled, so the model never reaches for a
    disabled tool.

    Pass ``proposal_sink`` (an empty list) to enable the ``propose_verdict`` tool;
    any proposals made during the run will be appended there. Pass ``hunt_sink``
    the same way for ``propose_hunt`` (the general chat's proposal). Both are
    registered HERE (not in the toolset) because they are chat-only and own
    their sink closures, and both are OPT-IN: with no sink the tool is absent
    from the schema, which is what keeps the general chat from proposing
    verdicts and the investigation chat from proposing hunts.

    ``default_window`` widens the implicit window on the two time-windowed query
    tools for a chat with no alert to anchor to (the general chat's questions
    are network-wide and span days, not the ±30 minutes around an alert).
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

    if hunt_sink is not None:

        @agent.tool_plain
        async def propose_hunt(objective: str, why: str) -> str:
            """Propose a threat hunt for a question that genuinely needs a SWEEP.

            Use this ONLY when answering requires looking across many hosts or a
            long time window — more than the read tools can cover in this turn.
            If you can answer now, answer now.

            `objective` is the hunt brief YOU write, sharpened by what you have
            already seen: name the behaviour, the datasets, the hosts and the time
            window. `why` is one line on what the sweep would settle that this
            turn could not. This does NOT start anything — it surfaces a 'Start
            hunt' control, and the analyst decides.
            """
            hunt_sink.append({"objective": objective, "why": why})
            return (
                "Hunt proposal recorded. The analyst will see a Start-hunt control; "
                "finish your answer with what you already established."
            )

    register_read_tools(agent, ctx, role="chat", default_window=default_window)

    return agent
