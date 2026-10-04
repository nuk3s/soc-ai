"""Post-turn grounding check for the chat agent's free-text answer.

The chat agent answers in prose. A read-only assistant that *rationalises* instead of
*investigating* will state concrete per-event facts — a hostname, an internal domain,
SMB/file-share activity, a specific IP — that it never actually pulled. The canonical
failure: a turn that made ZERO tool calls yet asserts ``DESKTOP-JSM4N2P`` resolved
``ad.local`` / ``wsus.internal`` and touched SMB shares, none of which is real.

This is the narrative analogue of :mod:`soc_ai.agent.proposal_validation` (the #49
evidence-aware grader pattern): a model-agnostic grader, not a voice-tuner. It detects
concrete artifact *assertions* in the answer text, then checks each against the
evidence corpus the turn actually had — (a) tool results from THIS turn, plus (b) the
seeded investigation context (alert / verdict / rationale / summary). An artifact that
appears in EITHER is grounded. We only raise a caveat when the answer asserts such
artifacts and NONE of them are grounded — so the alert's own host/IP/domain (which is
in the seed context) never trips it. Grounding is plain token/substring presence
against the corpus; no model is consulted.
"""

from __future__ import annotations

import fnmatch
import itertools
import json
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any

from soc_ai.dossier.coverage import HostCoverage
from soc_ai.dossier.coverage import describe as describe_coverage

# Ground-or-strip (2026-08-20, the owner's ruling; 2026-08-21: never bannered).
# A 2026-08-05 chat turn shipped a caveat banner naming its suspect claims
# inline, and a 2026-08-20 dogfood turn shipped one listing ordinary prose
# fragments ("closest-preceding", "package-update") as "unverified hostnames".
# The quiet line that replaced the banner ("Some unverifiable specifics were
# removed from this reply.") and the "(unverified)" placeholder were still the
# grounder talking to the analyst: a 2026-10-02 host chat reply carried both.
# `redact_ungrounded` now takes each claim out with its clause and says
# nothing. When nothing is left, the reply is this line, because an empty
# reply reads as an answer.
NOTHING_GROUNDED_REPLY = (
    "No statement in this answer had support in a tool result of this turn. "
    "Ask again, and name the host, the address or the dataset to check."
)


# Cap on artifacts named in a correction prompt — enough to be actionable
# without letting a pathological answer blow the turn's context budget.
_REGROUND_CAP = 8


def regrounding_instruction(ungrounded: list[str]) -> str:
    """Correction prompt for an answer that asserted ungrounded artifacts.

    The validator has always been able to NAME the fabricated claims; until now
    it only warned the analyst about them. Feeding the same finding back to the
    agent turns a caveat into a fix: verify the claim with a tool call, or take
    it out.

    The wording matters in two ways learned from live failures. It offers only
    those two resolutions — never "hedge it", because a softened fabrication is
    still a fabrication and reads as analysis. And it explicitly forbids
    manufacturing support, since the adjacent failure mode is an agent
    "grounding" a claim by describing a tool result it never received (the
    fabricated-tool-citation class this module already guards separately).

    Returns "" when there is nothing to correct, so the caller can treat an
    empty string as "no retry needed".
    """
    if not ungrounded:
        return ""
    shown = ungrounded[:_REGROUND_CAP]
    listing = ", ".join(f"`{a}`" for a in shown)
    more = (
        "" if len(ungrounded) <= _REGROUND_CAP else f" (and {len(ungrounded) - _REGROUND_CAP} more)"
    )
    return (
        "\n\nCORRECTION REQUIRED. Your previous answer stated these as observed "
        f"facts, but none of them appear in this turn's tool results or in the "
        f"investigation's evidence: {listing}{more}.\n"
        "Rewrite the answer. For EACH claim above, do exactly one of:\n"
        "  1. Call a tool that actually establishes it, then state it citing that "
        "tool result; or\n"
        "  2. Remove the claim entirely.\n"
        "Do NOT soften, hedge or re-word an unsupported claim to make it sound "
        "tentative. An unverified assertion is still unverified. Do NOT describe "
        "a tool result you did not receive. If a claim cannot be verified, say "
        "plainly that it is unknown and what you would need to check.\n"
        "Write the whole answer again for the analyst. Do not mention this correction, "
        "a removal or grounding in the answer."
    )


def redact_ungrounded(answer: str, ungrounded: list[str]) -> str:
    """Ground-or-strip's terminal half: take each ungrounded artifact out with its clause.

    The clause of a list item is the item: "no `a`, `b` or `c` data" loses `b`
    and keeps the rest of the sentence. Anywhere else the clause is the
    sentence, and a line that loses every sentence goes whole, its bullet
    included. No placeholder takes the place of a claim, and no line says that
    one went: a 2026-10-02 host chat reply carried "(unverified)" twice in one
    sentence and closed with "Some unverifiable specifics were removed". The
    match ignores case, takes every occurrence, and never starts or ends inside
    a longer token, so `192.0.2.6` cannot take out a sentence about
    `192.0.2.61`. Longest-first, as before, so a shorter artifact that is a
    prefix of a longer one cannot cut the longer one apart.
    """
    artifacts = sorted({a for a in ungrounded if a}, key=len, reverse=True)
    if not artifacts:
        return answer
    folded = {a.casefold() for a in artifacts}
    text = _ENUMERATION.sub(lambda m: _without_items(m.group(0), folded), answer)
    patterns = [_token_pattern(a) for a in artifacts]
    return strip_sentences(text, lambda sentence: any(p.search(sentence) for p in patterns))


def _token_pattern(artifact: str) -> re.Pattern[str]:
    """``artifact`` as a whole token: not inside a longer name or address."""
    return re.compile(rf"(?<![\w.-]){re.escape(artifact)}(?![\w-]|\.\w)", re.IGNORECASE)


# An item of an inline list: a code span, or a bare dotted or colon-joined
# token (a name, an address, an address with a port).
_ITEM = r"(?:`[^`\n]+`|(?<![\w`.:-])[A-Za-z0-9_-]+(?:[.:][A-Za-z0-9_-]+)+(?![\w`]|[.:]\w))"
_ITEM_RE = re.compile(_ITEM)
_JOIN = r"(?:[ \t]*,[ \t]*(?:(?:and|or)[ \t]+)?|[ \t]+(?:and|or)[ \t]+)"
_ENUMERATION = re.compile(rf"{_ITEM}(?:{_JOIN}{_ITEM})+", re.IGNORECASE)


def _without_items(run: str, folded: set[str]) -> str:
    """An inline list without the items in ``folded``, its conjunction kept.

    A list that would lose every item comes back unchanged: the sentence pass
    then takes the whole sentence out.
    """
    spans = list(_ITEM_RE.finditer(run))
    items = [m.group(0) for m in spans]
    joins = [run[a.end() : b.start()] for a, b in itertools.pairwise(spans)]
    keep = [item for item in items if item.strip("`").casefold() not in folded]
    if len(keep) == len(items) or not keep:
        return run
    words = [w for j in joins for w in re.findall(r"\b(?:and|or)\b", j, re.IGNORECASE)]
    conjunction = words[-1] if words else ""
    oxford = bool(joins) and bool(re.match(r"\s*,\s*(?:and|or)\s", joins[-1], re.IGNORECASE))
    if len(keep) == 1:
        return keep[0]
    if not conjunction:
        return ", ".join(keep)
    if len(keep) == 2:
        return f"{keep[0]} {conjunction} {keep[1]}"
    return f"{', '.join(keep[:-1])}{',' if oxford else ''} {conjunction} {keep[-1]}"


# A sentence ends at . ! or ? and any closing bold, code or quote marks, before
# whitespace or the end of the line. A dotted name has no space after its dots.
_SENTENCE_END = re.compile(r"[.!?]+(?:\*\*|__|[*_`\"')\]])*(?=\s|$)")
# A list bullet, a list number, a heading mark or a quote mark before the text.
_LINE_LEAD = re.compile(r"^\s*(?:[-*+•]\s+|\d+[.)]\s+|#{1,6}\s+|>\s+)?")


def _split_sentences(body: str) -> list[str]:
    out: list[str] = []
    start = 0
    for m in _SENTENCE_END.finditer(body):
        out.append(body[start : m.end()].strip())
        start = m.end()
    out.append(body[start:].strip())
    return [s for s in out if s]


def strip_sentences(text: str, drop: Callable[[str], bool]) -> str:
    """``text`` without each sentence that ``drop`` names.

    Works line by line, so a list keeps its shape. A line that loses every
    sentence goes whole, its bullet included. Paragraph breaks stay, and no run
    of blank lines is left behind. Text with nothing to drop comes back as it
    was, byte for byte.
    """
    lines: list[str] = []
    changed = False
    for line in text.split("\n"):
        if not line.strip():
            lines.append("")
            continue
        lead = _LINE_LEAD.match(line)
        prefix = lead.group(0) if lead else ""
        sentences = _split_sentences(line[len(prefix) :])
        kept = [s for s in sentences if not drop(s)]
        if len(kept) == len(sentences):
            lines.append(line)
            continue
        changed = True
        if kept:
            lines.append(prefix + " ".join(kept))
    if not changed:
        return text
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()


# What a model writes about the correction retry in place of the answer. The
# retry prompt asks for none of it; this takes out what comes anyway.
_CORRECTION_TALK = re.compile(
    r"\b(?:the correction is now|properly grounded|as corrected"
    r"|corrected (?:answer|reply|version))\b",
    re.IGNORECASE,
)


def strip_correction_talk(answer: str) -> str:
    """``answer`` without the sentences that talk about the correction retry.

    Production 2026-10-02: "The correction is now properly grounded: this host
    ships no endpoint process events." The analyst never saw a correction, so
    a sentence about one is the grounder's vocabulary leaking into the reply.
    """
    return strip_sentences(answer, lambda sentence: bool(_CORRECTION_TALK.search(sentence)))


# ── Artifact detectors ──────────────────────────────────────────────────────
# Each pattern pulls *concrete identity claims* out of free text. We deliberately
# match the specific shapes a hallucination invents (Windows hostnames, FQDNs,
# internal domains, dotted IPs, JA3 hashes) rather than trying to parse prose.

# Windows / NetBIOS-style host labels: DESKTOP-XXXX, WIN11-01, DC01, SRV-FILE2 …
# Case-insensitive so the regex still FINDS a candidate written in lowercase
# (e.g. "desktop-jsm4n2p") or backticked lowercase — the char classes are
# ASCII-only, so IGNORECASE stays ASCII. Matching case-insensitively does not
# mean every case qualifies, though: `_hostname_qualifies` below is a second,
# non-regex gate a match must also clear, and as of 2026-08-21 it rejects
# anything with a lowercase letter in it unless backticked (see that
# function's docstring) — so this flag's practical job is narrower than it
# looks, mostly keeping backticked-lowercase names findable.
#
# The SHAPE alone over-matches: any hyphen-joined pair of alnum runs is also
# what ordinary hyphenated English compounds look like ("closest-preceding",
# "package-update"), and a 2026-08-20 dogfood turn shipped exactly those as a
# caveat banner's "hostnames".
_HOSTNAME = re.compile(
    r"\b(?:[A-Z][A-Z0-9]{1,14}-[A-Z0-9]{2,15}|DESKTOP-[A-Z0-9]{3,})\b", re.IGNORECASE
)
# Dotted FQDNs / domains: ad.local, wsus.internal, foo.corp.example.com.
# Requires at least one dot and an alphabetic TLD-ish final label (>=2 chars) so
# we don't catch version strings or "e.g".
#
# Two changes keep it LINEAR on dot-dense text (a payload_printable / DNS blob a
# model can echo into the narrative) instead of the old quadratic backtracking:
#   * the label-dot group repeats a BOUNDED {1,126} times (127 labels incl. the
#     TLD is the DNS maximum), so a failing match at each dotted start position
#     does O(1) work instead of re-walking the whole chain — this is what removes
#     the O(n^2);
#   * the optional interior run is POSSESSIVE (``?+``) so a single label has one
#     decomposition and never backtracks internally.
# Both preserve matching semantics for every real domain (verified by a
# same-matches test); only pathological >126-label strings differ.
_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?+\.){1,126}[a-zA-Z]{2,24}\b"
)
# IPv4 dotted-quad.
_IPV4 = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
# JA3 / JA3S / MD5-shaped 32-hex fingerprints.
_JA3 = re.compile(r"\b[0-9a-fA-F]{32}\b")

# SMB / file-share *activity* claims (a behaviour, not an identifier). We treat a
# bare mention as an artifact only to require that some SMB/file evidence exists;
# the flag is driven by the identifier artifacts, with SMB as a supporting signal.
_SMB_CLAIM = re.compile(
    r"\b(?:smb|smb_files|file[\s-]?share|file[\s-]?shares|\\\\[A-Za-z0-9._-]+\\)\b",
    re.IGNORECASE,
)

# Domain-shaped tokens that are almost never real artifacts — common filenames,
# library/method dotted forms, and prose fragments that the FQDN regex would grab.
# Keeping this list short and obvious avoids tuning to any one model's voice.
_DOMAIN_STOP_SUFFIXES = (
    ".exe",
    ".dll",
    ".log",
    ".txt",
    ".json",
    ".py",
    ".md",
)
_DOMAIN_STOP_EXACT = {"e.g", "i.e", "etc.al"}

# ES / Zeek / Suricata field-namespace prefixes. A dotted token that *starts with*
# one of these is a field PATH the analyst (and our own prompt) names — e.g.
# `zeek.dns`, `event.dataset`, `dns.question.name`, `host.name`, `source.ip`,
# `network.community_id` — NOT a resolved domain. Excluding them is what keeps a
# perfectly good answer that says "I queried zeek.dns" from being flagged.
_FIELD_NAMESPACES = (
    "event.",
    "host.",
    "source.",
    "destination.",
    "network.",
    "dns.",
    "http.",
    "tls.",
    "ssl.",
    "url.",
    "file.",
    "zeek.",
    "suricata.",
    "sigma.",
    "rule.",
    "user.",
    "client.",
    "server.",
    "ja3.",
    "ja3s.",
    "related.",
    "threat.",
    "observer.",
    "ecs.",
    "log.",
    "agent.",
    "process.",
    "tags.",
)


@dataclass
class NarrativeArtifacts:
    hostnames: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    ips: list[str] = field(default_factory=list)
    ja3: list[str] = field(default_factory=list)
    smb: bool = False

    def identifier_assertions(self) -> list[str]:
        """Concrete identity artifacts (everything except the bare SMB-behaviour flag)."""
        return [*self.hostnames, *self.domains, *self.ips, *self.ja3]

    def any_assertion(self) -> bool:
        return bool(self.identifier_assertions()) or self.smb


@dataclass
class NarrativeGrounding:
    grounded: bool
    """True when the narrative is acceptable (no ungrounded artifacts, or none asserted)."""
    asserted: list[str] = field(default_factory=list)
    ungrounded: list[str] = field(default_factory=list)
    reason: str | None = None


def _looks_like_domain(token: str) -> bool:
    low = token.lower().rstrip(".")
    if low in _DOMAIN_STOP_EXACT:
        return False
    if any(low.endswith(s.rstrip(".")) for s in _DOMAIN_STOP_SUFFIXES):
        return False
    # A log field PATH (event.dataset, zeek.dns, host.name …) is not a domain.
    if low.startswith(_FIELD_NAMESPACES):
        return False
    # An all-numeric final label means it's actually an IP — handled by _IPV4.
    return not low.split(".")[-1].isdigit()


def _hostname_qualifies(answer: str, match: re.Match[str]) -> bool:
    """Second gate a `_HOSTNAME`-shaped match must clear to count as an artifact.

    The regex shape (alnum-hyphen-alnum) is identical for a real machine name
    and for ordinary hyphenated English prose ("closest-preceding",
    "malicious-external", "origin-chain", "package-update" — the exact tokens a
    2026-08-20 dogfood turn shipped as a caveat banner's "hostnames").

    2026-08-20 ruling: a match counted if it contained a digit OR an uppercase
    letter ANYWHERE, or was backticked. That was still too loose — ordinary
    security prose is full of capitalized or digit-bearing hyphenated terms
    ("C2-like", "C2-style", "Origin-chain", "Tor-check", "Cloudflare-fronted").
    A live 2026-08-21 turn burned BOTH of its regrounding attempts chasing
    these as "unverified hostnames" before the terminal check flagged two of
    them again and redacted them out of an otherwise-correct answer.

    2026-08-21 ruling (this fix): a match counts only if it (a) is wrapped in
    backticks in the reply, or (b) is NetBIOS-shaped — EVERY character in the
    token is uppercase or a digit, i.e. no lowercase letter anywhere
    (``DESKTOP-JSM4N2P``, ``WIN-AB12CD``). A single lowercase letter anywhere —
    even next to a digit or an initial capital, as in "C2-style" or
    "Origin-chain" — now reads as prose, not a machine name. This is a further
    owner-ratified narrowing of the same tradeoff: false negatives on a rare
    unformatted-but-real hostname (now including ones with a stray digit, e.g.
    an unbackticked "desktop-jsm4n2p") beat flagging ordinary hyphenated
    security vocabulary as unverified. Code-formatting (backticks) remains the
    escape hatch for a genuine unformatted name.
    """
    token = match.group(0)
    if not any(ch.islower() for ch in token):
        return True
    start, end = match.span()
    return answer[start - 1 : start] == "`" and answer[end : end + 1] == "`"


def extract_artifacts(answer: str) -> NarrativeArtifacts:
    """Pull concrete identity claims out of the answer's free text."""
    ips = sorted({m.group(0) for m in _IPV4.finditer(answer)})
    ip_set = set(ips)
    hostnames = sorted(
        {m.group(0) for m in _HOSTNAME.finditer(answer) if _hostname_qualifies(answer, m)}
    )
    ja3 = sorted({m.group(0).lower() for m in _JA3.finditer(answer)})
    domains = sorted(
        {
            m.group(0)
            for m in _DOMAIN.finditer(answer)
            if m.group(0) not in ip_set and _looks_like_domain(m.group(0))
        }
    )
    smb = bool(_SMB_CLAIM.search(answer))
    return NarrativeArtifacts(hostnames=hostnames, domains=domains, ips=ips, ja3=ja3, smb=smb)


# ── Names a tool call used ──────────────────────────────────────────────────
# A dotted name. A "*" may stand for a label or the end of one.
_DOTTED_NAME = r"[A-Za-z0-9_*][\w*-]*(?:\.[\w*-]+)+"
# A field on the left of a comparison: "dhcp.hostname:", "winlog.event_id ==".
_QUERY_FIELD = re.compile(rf"(?<![\w.*-])({_DOTTED_NAME})\s*(?:==|!=|>=|<=|=|:|>|<)")
# The value of a dataset field: one name, or a list in brackets.
_QUERY_DATASET = re.compile(
    r"\b(?:event\.dataset|event\.module|data_stream\.dataset)\s*(?:==|!=|=|:|\s+in\s+)\s*"
    r"(?:\(([^)]*)\)|\[([^\]]*)\]|[\"']?([\w.*-]+)[\"']?)",
    re.IGNORECASE,
)
# The fields a pipe stage names: "| groupby event.dataset, host.name".
_QUERY_STAGE = re.compile(
    r"\|\s*(?:groupby|sortby|table|fields|count\s+by|by)\s+([^|]+)", re.IGNORECASE
)
# Named arguments that hold a dataset or a field.
_NAME_ARGUMENTS = frozenset({"dataset", "datasets", "field", "fields"})


def _tool_args(call: dict[str, object]) -> dict[str, Any]:
    raw = call.get("args")
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except ValueError:
            return {}
    return raw if isinstance(raw, dict) else {}


def _query_names(query: str) -> set[str]:
    found = {m.group(1) for m in _QUERY_FIELD.finditer(query)}
    for m in _QUERY_DATASET.finditer(query):
        listed = next((g for g in m.groups() if g), "")
        found.update(re.findall(_DOTTED_NAME, listed))
    for m in _QUERY_STAGE.finditer(query):
        found.update(re.findall(_DOTTED_NAME, m.group(1)))
    return {name.lower() for name in found}


def argument_names(tool_calls: Iterable[dict[str, object]]) -> set[str]:
    """The dataset and field names this turn's tool calls used, lower case.

    Read from an OQL query (the value of a dataset field, a field on the left
    of a comparison, the fields of a pipe stage) and from a named ``dataset``
    or ``field`` argument. A value the call searched for is not read: a query
    for a made-up domain does not make the domain observed. A name may hold a
    "*", and :func:`_names_used` matches it only when a literal label comes
    first.
    """
    names: set[str] = set()
    for call in tool_calls:
        for key, value in _tool_args(call).items():
            if key in _NAME_ARGUMENTS:
                values = value if isinstance(value, list) else [value]
                names.update(v.strip().lower() for v in values if isinstance(v, str))
            elif key == "query" and isinstance(value, str):
                names.update(_query_names(value))
    return {name for name in names if "." in name}


def _names_used(artifact: str, used: set[str]) -> bool:
    """True when ``artifact`` is a name in ``used``, its namespace, or a "*" name covers it.

    A namespace is a leading run of whole labels: "endpoint.events" is the
    namespace of "endpoint.events.*" and of "endpoint.events.network". A
    pattern needs a literal first label: "endpoint.events.*" covers
    "endpoint.events.network", and "*.internal" covers nothing.
    """
    low = artifact.lower()
    if low in used or any(name.startswith(low + ".") for name in used):
        return True
    return any(
        "*" in name and "*" not in name.split(".", 1)[0] and fnmatch.fnmatchcase(low, name)
        for name in used
    )


def _corpus(seed_context: str, tool_evidence: list[dict[str, object]]) -> str:
    """Lower-cased evidence corpus: seed context + every tool result this turn."""
    parts = [seed_context or ""]
    for e in tool_evidence:
        parts.append(str(e.get("result", "")))
        parts.append(str(e.get("tool", "")))
    return "\n".join(parts).lower()


def check_narrative_grounding(
    answer: str,
    *,
    seed_context: str,
    tool_evidence: list[dict[str, object]],
    tool_calls: Iterable[dict[str, object]] = (),
) -> NarrativeGrounding:
    """Grade the answer's concrete artifacts against the turn's evidence corpus.

    ``seed_context`` is the per-investigation block embedded in the system prompt
    (alert summary + verdict + rationale + analyst summary). ``tool_evidence`` is the
    ``[{"tool", "result"}]`` list extracted from the run — empty when the turn made no
    tool calls. An artifact is GROUNDED if its (case-insensitive) text appears anywhere
    in the corpus. The narrative is flagged ONLY when it asserts concrete identifier
    artifacts and not one of them is grounded — so the alert's own host/IP/domain, which
    lives in the seed context, is always grounded and never trips a false positive.

    ``tool_calls`` is the ``[{"tool", "args"}]`` list of this turn's calls. A
    dotted name that a call used as a dataset or a field is grounded too, a
    zero-hit query included: the query that found nothing grounds the claim
    that the dataset holds nothing (see :func:`argument_names`).
    """
    artifacts = extract_artifacts(answer)
    identifiers = artifacts.identifier_assertions()

    # No concrete identity claim → nothing to ground; a bare SMB mention with no
    # identifiers is too weak to flag on its own (avoids false positives on prose
    # like "I'd want to check for SMB activity").
    if not identifiers:
        return NarrativeGrounding(grounded=True, asserted=[], ungrounded=[])

    corpus = _corpus(seed_context, tool_evidence)

    # Every identity artifact (hostname / domain / IP / JA3) the answer states as an
    # observed per-event fact must appear in the evidence corpus (a tool result this
    # turn or the seeded alert context). EVERY ungrounded one is flagged — a single
    # grounded artifact does NOT excuse the fabricated ones. The canonical failure is
    # exactly that mixed shape: anchor on the alert's own (grounded) host/IP, then
    # embellish with a fabricated hostname / internal DNS / SMB story (the
    # DESKTOP-JSM4N2P / ad.local case). "One ground → accept" would wave it through.
    used = argument_names(tool_calls)
    domains = {d.lower() for d in artifacts.domains}
    ungrounded = [
        a
        for a in identifiers
        if a.lower() not in corpus and not (a.lower() in domains and _names_used(a, used))
    ]
    # SMB / file-share activity asserted with no SMB evidence anywhere in the corpus.
    smb_unsupported = artifacts.smb and not any(
        tok in corpus for tok in ("smb", "file share", "file-share", "fileshare")
    )
    if smb_unsupported:
        # The claim rides in `ungrounded` as the text the answer actually used
        # ("SMB", "file shares"), not as a descriptive label: the regrounding
        # prompt and `redact_ungrounded` both work on that list, and neither can
        # act on a label that never appears in the answer. Before this, an
        # SMB-only failure came back with an empty list, so the chat engine
        # skipped the retry, stripped nothing, and still told the analyst
        # something had been removed while the claim shipped verbatim.
        seen: dict[str, str] = {}
        for m in _SMB_CLAIM.finditer(answer):
            seen.setdefault(m.group(0).lower(), m.group(0))
        ungrounded.extend(seen.values())

    if not ungrounded:
        return NarrativeGrounding(grounded=True, asserted=identifiers, ungrounded=[])

    reason = (
        "answer asserts per-event fact(s) "
        + ", ".join(repr(a) for a in ungrounded[:6])
        + (" …" if len(ungrounded) > 6 else "")
        + " that appear in neither a tool result nor the investigation context"
    )
    return NarrativeGrounding(
        grounded=False, asserted=identifiers, ungrounded=ungrounded, reason=reason
    )


# ── Host telemetry claims ───────────────────────────────────────────────────
# Production held twelve sentences like "No host-level telemetry exists" and
# "no host-level endpoint telemetry exists for <host>" about one Linux server
# that shipped system logs, auth logs and osquery. Every probe behind them
# asked Elastic Defend, which the host never ran. A sentence of this class is
# a claim about EVERY plane of a host. It is false while any plane is present.
#
# The patterns match the generic claim only. A plane-level sentence ("no
# endpoint process telemetry", "no host-level process visibility") names the
# plane it is about, and it is true on such a host, so it never matches: a
# plane word between the qualifier and the noun breaks every pattern below.
_HOST_GAP_CLAIMS: tuple[re.Pattern[str], ...] = (
    # "no host-level endpoint telemetry", "No host-level telemetry exists",
    # "(no host-level events)", "no host telemetry on X", "no host data".
    re.compile(
        r"\bno\s+host(?:[- ](?:level|side|based))?\s+(?:endpoint\s+)?"
        r"(?:telemetry|events?|data|visibility)\b",
        re.IGNORECASE,
    ),
    # "host-level endpoint telemetry is not indexed for this host".
    re.compile(
        r"\bhost[- ]level\s+(?:endpoint\s+)?telemetry\s+(?:is|was|are)\s+not\b",
        re.IGNORECASE,
    ),
    # "endpoint plane does not cover <host>", "endpoint telemetry does not
    # cover this host".
    re.compile(
        r"\b(?:endpoint|host)\s+(?:plane|telemetry|agent|coverage)\s+(?:does|did)\s+not\s+cover\b",
        re.IGNORECASE,
    ),
    # "not covered by endpoint telemetry" (but not "by endpoint process telemetry").
    re.compile(
        r"\bnot\s+covered\s+by\s+(?:any\s+)?(?:host|endpoint)\s+(?:telemetry|agent)\b",
        re.IGNORECASE,
    ),
    # "without host telemetry", "lacks host-level telemetry".
    re.compile(
        r"\b(?:lacks?|without)\s+(?:any\s+)?host(?:[- ]level)?\s+(?:telemetry|visibility)\b",
        re.IGNORECASE,
    ),
    # "no endpoint telemetry for <host>" (but not "no endpoint process telemetry").
    re.compile(r"\bno\s+endpoint\s+(?:telemetry|agent|coverage|visibility)\b", re.IGNORECASE),
)

# A sentence ends at . ! or ? before whitespace, or at a line break. A dotted
# name or a field path ("host.ip:192.0.2.41") has no space after its dots.
_SENTENCE_BREAK = re.compile(r"((?<=[.!?])[ \t]+|\n+)")


def claims_no_host_telemetry(sentence: str) -> bool:
    """True when ``sentence`` says a host has no host telemetry at all."""
    return any(p.search(sentence) for p in _HOST_GAP_CLAIMS)


def rewrite_host_gap_claims(
    text: str,
    replacement: Callable[[str], str | None],
) -> tuple[str, int]:
    """Rewrite each sentence of ``text`` that claims a host has no host telemetry.

    ``replacement`` gets the claiming sentence and returns the text to put in
    its place: the coverage sentences of the host it names, ``""`` to strip it,
    or ``None`` to keep it. A replacement that an earlier sentence in the same
    text already inserted is not inserted twice. Line breaks and the other
    sentences stay as they were. Returns the new text and the count of
    sentences changed.
    """
    if not text:
        return text, 0
    parts = _SENTENCE_BREAK.split(text)
    changed = 0
    inserted: set[str] = set()
    out: list[str] = []
    drop_break = False
    for i, part in enumerate(parts):
        if i % 2 == 1:
            # A stripped sentence takes the break after it, so no blank
            # line or double space is left behind.
            if not drop_break:
                out.append(part)
            drop_break = False
            continue
        if not claims_no_host_telemetry(part):
            out.append(part)
            continue
        new = replacement(part)
        if new is None:
            out.append(part)
            continue
        changed += 1
        if new and new not in inserted:
            inserted.add(new)
            # Keep a bullet or a list number that sat before the sentence.
            lead = re.match(r"^\s*(?:[-*\u2022]\s+|\d+[.)]\s+)?", part)
            out.append((lead.group(0) if lead else "") + new)
        else:
            drop_break = True
    if not changed:
        return text, 0
    return "".join(out).strip(), changed


@dataclass(frozen=True)
class CoverageSubject:
    """One host a report may write about, with the coverage soc-ai read for it.

    ``label`` is the name a replacement sentence uses. ``tokens`` are the
    spellings a sentence may name the host by: its address, its agent name
    and the names the coverage read searched.
    """

    label: str
    tokens: tuple[str, ...]
    coverage: HostCoverage


def coverage_subject(address: str, coverage: HostCoverage) -> CoverageSubject:
    """A subject for one address and the coverage read for it."""
    agent = coverage.agent
    label = agent.name if agent is not None and agent.name else address
    tokens = {address.lower(), *coverage.host_names()}
    return CoverageSubject(
        label=label, tokens=tuple(sorted(t for t in tokens if t)), coverage=coverage
    )


def _names_subject(sentence: str, subject: CoverageSubject) -> bool:
    low = sentence.lower()
    return any(
        re.search(rf"(?<![\w.-]){re.escape(token)}(?![\w-])", low) for token in subject.tokens
    )


def coverage_replacer(subjects: list[CoverageSubject]) -> Callable[[str], str | None]:
    """The replacement for a "no host telemetry" claim, read from the coverage.

    A claim that names a host gets that host's coverage sentences when the
    host ships any plane. A claim that names no host gets them only when every
    host the report concerns ships a plane, because then the claim is false
    whichever host it meant. A claim about a host that ships nothing, or whose
    coverage soc-ai could not read, stays: it may be true.
    """

    def _replace(sentence: str) -> str | None:
        named = [s for s in subjects if _names_subject(sentence, s)]
        targets = named or subjects
        if not targets or not all(t.coverage.covered for t in targets):
            return None
        return " ".join(
            line for t in targets for line in describe_coverage(t.coverage, subject=t.label)
        )

    return _replace


def ground_host_coverage_claims(report: Any, subjects: list[CoverageSubject]) -> tuple[Any, int]:
    """Rewrite the "no host telemetry" claims of a triage report from the coverage.

    Reads the summary, the field reconciliation and each recommended action's
    rationale. Returns the report (a copy when anything changed) and the count
    of sentences rewritten.
    """
    if not subjects:
        return report, 0
    replace = coverage_replacer(subjects)
    changed = 0
    update: dict[str, Any] = {}
    summary, n = rewrite_host_gap_claims(str(getattr(report, "summary", "") or ""), replace)
    if n:
        update["summary"] = summary
        changed += n
    reconciliation = getattr(report, "field_reconciliation", None)
    if isinstance(reconciliation, str):
        text, n = rewrite_host_gap_claims(reconciliation, replace)
        if n:
            update["field_reconciliation"] = text
            changed += n
    actions = list(getattr(report, "recommended_actions", None) or [])
    new_actions = []
    for action in actions:
        text, n = rewrite_host_gap_claims(str(getattr(action, "rationale", "") or ""), replace)
        if n:
            changed += n
            new_actions.append(action.model_copy(update={"rationale": text}))
        else:
            new_actions.append(action)
    if any(a is not b for a, b in zip(actions, new_actions, strict=True)):
        update["recommended_actions"] = new_actions
    if not update:
        return report, 0
    return report.model_copy(update=update), changed
