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

import re
from dataclasses import dataclass, field

# A trailing caveat appended to the stored answer when the narrative asserts
# concrete artifacts that are grounded in NEITHER a tool result NOR the seed context.
# Used for ZERO-TOOL turns, where "not backed by a tool result" is literally true.
UNVERIFIED_CAVEAT = (
    "\n\n⚠ Unverified: the above was not backed by a tool result or the "
    "investigation's evidence; treat as a hypothesis, not a finding."
)

# Bound on how many suspect artifacts the scoped caveat names inline.
_SCOPED_CAVEAT_CAP = 4


def scoped_unverified_caveat(ungrounded: list[str]) -> str:
    """Caveat for a turn that DID run tools but asserted some ungrounded artifacts.

    The blanket :data:`UNVERIFIED_CAVEAT` under a visible tool-call footer reads
    as a contradiction — "not backed by a tool result" directly beneath five
    tool calls (dogfood 2026-07-15). Name the specific suspect claims instead,
    so the analyst knows exactly which parts to double-check and which parts
    the tool output stands behind.
    """
    shown = [f"`{a}`" for a in ungrounded[:_SCOPED_CAVEAT_CAP]]
    listing = ", ".join(shown) + (" …" if len(ungrounded) > _SCOPED_CAVEAT_CAP else "")
    return (
        f"\n\n⚠ Partially unverified: {listing} "
        "do not appear in this turn's tool results or the investigation's "
        "evidence — verify before acting on them. The reply's other specifics "
        "are grounded in the tool output."
    )


# ── Artifact detectors ──────────────────────────────────────────────────────
# Each pattern pulls *concrete identity claims* out of free text. We deliberately
# match the specific shapes a hallucination invents (Windows hostnames, FQDNs,
# internal domains, dotted IPs, JA3 hashes) rather than trying to parse prose.

# Windows / NetBIOS-style host labels: DESKTOP-XXXX, WIN11-01, DC01, SRV-FILE2 …
# Case-insensitive: a fabricated hostname written lowercase (common LLM prose,
# e.g. "desktop-jsm4n2p") is the same hallucination as its all-caps form and must
# be caught too — the char classes are ASCII-only, so IGNORECASE stays ASCII.
_HOSTNAME = re.compile(
    r"\b(?:[A-Z][A-Z0-9]{1,14}-[A-Z0-9]{2,15}|DESKTOP-[A-Z0-9]{3,})\b", re.IGNORECASE
)
# Dotted FQDNs / domains: ad.local, wsus.internal, foo.corp.example.com.
# Requires at least one dot and an alphabetic TLD-ish final label (>=2 chars) so
# we don't catch version strings or "e.g".
_DOMAIN = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b")
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


def extract_artifacts(answer: str) -> NarrativeArtifacts:
    """Pull concrete identity claims out of the answer's free text."""
    ips = sorted({m.group(0) for m in _IPV4.finditer(answer)})
    ip_set = set(ips)
    hostnames = sorted({m.group(0) for m in _HOSTNAME.finditer(answer)})
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
) -> NarrativeGrounding:
    """Grade the answer's concrete artifacts against the turn's evidence corpus.

    ``seed_context`` is the per-investigation block embedded in the system prompt
    (alert summary + verdict + rationale + analyst summary). ``tool_evidence`` is the
    ``[{"tool", "result"}]`` list extracted from the run — empty when the turn made no
    tool calls. An artifact is GROUNDED if its (case-insensitive) text appears anywhere
    in the corpus. The narrative is flagged ONLY when it asserts concrete identifier
    artifacts and not one of them is grounded — so the alert's own host/IP/domain, which
    lives in the seed context, is always grounded and never trips a false positive.
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
    ungrounded = [a for a in identifiers if a.lower() not in corpus]
    # SMB / file-share activity asserted with no SMB evidence anywhere in the corpus.
    smb_unsupported = artifacts.smb and not any(
        tok in corpus for tok in ("smb", "file share", "file-share", "fileshare")
    )

    if not ungrounded and not smb_unsupported:
        return NarrativeGrounding(grounded=True, asserted=identifiers, ungrounded=[])

    detail = list(ungrounded)
    if smb_unsupported:
        detail.append("SMB/file-share activity")
    reason = (
        "answer asserts per-event fact(s) "
        + ", ".join(repr(a) for a in detail[:6])
        + (" …" if len(detail) > 6 else "")
        + " that appear in neither a tool result nor the investigation context"
    )
    return NarrativeGrounding(
        grounded=False, asserted=identifiers, ungrounded=ungrounded, reason=reason
    )
