"""The dossier as the model reads it: an ambient block, explicitly not evidence.

This is where "what IS this host?" reaches the agent's reasoning without the
agent having to ask. Everything about the rendering is shaped by two failures.

**The laundering failure.** An inferred role is a conclusion drawn from
telemetry a host can influence — the name it announces over DHCP, the banner it
serves, the ports it answers on. If that conclusion renders like a fact, a
verdict can end up resting on a machine that called itself ``pve-hypervisor``.
So the block leads with a heading that names itself system-inferred context and
NOT evidence, says operator values outrank inferred ones, and points at
``t_host_dossier`` as the citable route — citations resolve against the enriched
alert context, never against this text, and the model needs to be told that
rather than left to discover it by having a citation rejected.

**The silent-omission failure.** A block that describes one host and says
nothing about the other reads as "nothing notable about that one". Absence is
therefore stated out loud, and an unresolved field says *why* it is unresolved
(``stale`` / weak signal / no signal are three different answers). The one case
that renders nothing at all is when NO host has a record: a section whose entire
content is "we have no record of either address" is noise on every alert of a
deployment that has not swept yet, and it teaches the model to skip the section
that will matter once it has.

The block is prepended to a prompt that already carries the enriched alert, so
it pays for itself out of a budget: :data:`MAX_TOKENS_PER_HOST` and
:data:`MAX_TOKENS_TOTAL`, measured with the same estimator the enriched-context
trimmer uses. Truncation drops the descriptive tail first and keeps role,
criticality and policy — an operator who pastes a page of site policy into
``policy_notes`` must not be able to push the correlation signal out of the
model's window, and must not be able to lose their own policy either.

Rendering deliberately stays identifier-shaped where the alert is: IPs are
written exactly as the caller passes them, because the egress guard allocates
one label per spelling and the whole mechanic — "IP_01 is a hypervisor whose
policy forbids interactive SSH" — depends on the dossier's IP collapsing onto
the same ``IP_01`` the alert already carries. The block must therefore be
composed BEFORE the sanitize sweep, never appended after it.
"""

from __future__ import annotations

import dataclasses
import logging
import re
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from typing import TYPE_CHECKING, Any

from soc_ai.dossier.resolve import (
    OPERATOR_SOURCE,
    ResolvedDossier,
    ResolvedField,
    resolve_dossier_from_settings,
    unknown_dossier,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from soc_ai.agent.context import InvestigationContext

_LOGGER = logging.getLogger(__name__)


def estimate_tokens(text: str) -> int:
    """Token estimate, deferring to :mod:`soc_ai.agent.context_budget`.

    Imported lazily because ``soc_ai.dossier`` sits BELOW ``soc_ai.agent`` in the
    package layering, and the agent side imports this module at its own module
    scope (``orchestrator`` pulls in ``host_dossier_prompt_block``). Importing
    upward at module scope closes that loop: ``import soc_ai.dossier.prompt``
    before anything has imported ``soc_ai.agent`` raises ``ImportError`` on a
    partially-initialised module. It only ever worked because every real caller
    happened to touch an agent module first — a load order nothing enforced,
    which bit a deploy-verification script and a throwaway repro before this.
    """
    from soc_ai.agent.context_budget import estimate_tokens as _estimate  # noqa: PLC0415

    return _estimate(text)


# Per-host and whole-block ceilings, in `context_budget.estimate_tokens` units.
# Public because the orchestrator subtracts the block's cost from the enriched
# context's budget, and a test pins both against a pathological host.
MAX_TOKENS_PER_HOST = 250
MAX_TOKENS_TOTAL = 600

# How many hosts one block describes. Every caller that widened past the two
# alert endpoints — the alert's group events, a hunt objective, a chat thread —
# can name an arbitrary number of addresses, and each one costs a store read as
# well as prompt space. The cap lives HERE, with the token ceilings, so there is
# one answer to "how much of this prompt is asset context" and one place that
# says how many hosts were left out (:func:`_omitted_line`); a caller that
# trimmed its own list first would drop hosts the block never gets to mention.
MAX_PROMPT_HOSTS = 8

# How long the "a different machine appears to hold this address" note keeps
# being rendered after the rebind. `identity_rebound_at` is stamped and never
# cleared, so an unbounded note is permanent once written — see
# `_rebind_is_recent`. Roughly two default observation windows
# (`dossier_lookback_days` = 14): long enough for the operator to meet the note
# across several sweeps and for the `rebound` conflict prod (>= 3 disagreeing
# builds, at most one prompt per 14 days) to have had its chance to fire, short
# enough that it stops riding every alert forever. A module constant rather than
# a setting, like MAX_TOKENS_*: this renderer is deliberately pure, and the
# window is a readability judgement rather than site policy.
REBIND_NOTE_WINDOW_DAYS = 30

# Hard clamps on a single rendered value / evidence string. They are what makes
# the "never dropped" fields safe to keep: a 4,000-character operator policy is
# still rendered, just not in full.
_VALUE_CHARS = 240
_EVIDENCE_CHARS = 300

# Truncation ladder, applied per host and then (if the total still overflows)
# raised as a floor across every host. The order is the contract's: lose the
# behavioural baseline before the lifetime, the lifetime before the evidence
# strings, and the OS detail last. Role, criticality, policy and the "no
# dossier" line are not on the ladder at all — those are the fields that change
# a verdict.
_L_FULL = 0
_L_NO_BASELINE = 1
_L_NO_SEEN = 2
_L_NO_EVIDENCE = 3
_L_NO_DETAIL = 4
_LEVELS = range(_L_FULL, _L_NO_DETAIL + 1)

HEADING = "## Host dossier (system-inferred asset context — provenance-tagged, NOT evidence)"

_INTRO = (
    "Deterministic rules over telemetry, not a model. Operator-set values are "
    "authoritative. Do not cite these as evidence; if a claim rests on one, call "
    "`t_host_dossier` and cite the tool result. An `unknown` field states why it "
    "is unknown, and a host with no dossier is one the network sweep has no record "
    "of — neither is evidence that anything here is fine."
)

# Ports the classifier calls remote-access initiation, spelled out for the
# baseline line so "has never done this before" is a readable claim.
_REMOTE_ACCESS_LABEL = "SSH/RDP/WinRM"


def format_host_dossier_block(
    entries: list[ResolvedDossier],
    *,
    labels: Mapping[str, str] | None = None,
    now: datetime | None = None,
    omitted: int = 0,
) -> str:
    """Render resolved dossiers as the prompt block. ``""`` when there is nothing.

    *labels* tags a host with its role in the alert (``{"10.0.0.5": "source"}``);
    a host with no label renders as a bare address. Order is the caller's, so
    the source host reads first.

    *now* is the clock every relative label ("last seen 3m ago") and every
    time-bounded note are measured against; it defaults to the wall clock.
    Passing it explicitly keeps one render internally consistent with the
    resolve pass that produced *entries* — and is what makes anything
    time-bounded testable at all.

    *omitted* is how many hosts the caller already dropped before reading them
    (see :data:`MAX_PROMPT_HOSTS`). It is folded into the SAME trailing count
    the budget ladder writes, so a reader gets one number for "hosts this block
    does not describe" rather than one stated ceiling and one silent one.

    Empty output for empty input — and for input in which no host has a record —
    so a composition site can append the result unconditionally. That
    suppression BEATS *omitted*: when nothing was found, the whole block goes,
    trailing count included. It is the one place a remainder is not stated, and
    deliberately so — the alternative is a heading, an intro and a lone "(+3
    more hosts omitted)" describing no host at all, which is the noise the
    empty-output rule exists to prevent, and no shortened list is left behind to
    read as a complete one.
    """
    if not any(entry.found for entry in entries):
        return ""
    at = _aware(now) if now is not None else datetime.now(UTC)
    tags = dict(labels or {})
    rendered: list[str] = []
    for floor in _LEVELS:
        rendered = [_fit_host(entry, tags.get(entry.ip), floor=floor, now=at) for entry in entries]
        block = _assemble(rendered if not omitted else [*rendered, _omitted_line(omitted)])
        if estimate_tokens(block) <= MAX_TOKENS_TOTAL:
            return block
    # Every host is already at its minimal shape and the block still overflows
    # (many hosts, not verbose ones). Drop from the tail and SAY how many: a
    # silently shortened list is the omission failure this block exists to fix.
    return _drop_hosts(rendered, extra=omitted)


async def host_dossier_prompt_block(
    ips: Mapping[str, str],
    *,
    ctx: InvestigationContext,
    max_hosts: int = MAX_PROMPT_HOSTS,
    known_only: bool = False,
) -> str:
    """Read *ips* from the dossier store and render the block. Never raises.

    *ips* maps address -> its role in the alert (``"source"`` / ``"destination"``
    / ``"related event"`` / whatever the surface calls it), so the caller decides
    both the set and the order. Returns ``""`` — prefixed with a blank line
    otherwise — on every off-switch and every failure: a dossier read that fails
    must cost the investigation nothing, which is the same contract
    ``inventory_prompt_block`` carries.

    Callers pass everything they found and this function bounds it at
    *max_hosts*, reporting the remainder in the block's own omitted line. The
    cap is here rather than in each caller because it bounds two things at once
    — the prompt, and one store read per address — and because a caller that
    truncated first would have nothing left to declare.

    *known_only* drops hosts the sweep has no record of instead of stating the
    absence. Set it on every surface whose ADDRESSES CAME FROM FREE TEXT (a hunt
    objective, a chat thread), and leave it off on the alert path.

    The difference is not cosmetic, it is a grounding boundary.
    ``check_narrative_grounding`` grounds a claim by its PRESENCE IN THE CORPUS
    and never by verifying it, and the seed block is part of that corpus. A "no
    dossier" line therefore puts its own address into the corpus — harmless when
    the address came from the alert's typed fields, but on a free-text surface
    the address may have been typed by the analyst or produced by the MODEL on a
    previous turn, and rendering it would let it ground itself. On the alert path
    the absence stays load-bearing for the reason
    ``dossier_hosts_for_alert`` gives: the alert's own destination is a host
    under discussion, and silence about it reads as "nothing notable there".

    Both switches are read with ``getattr(..., False) is True`` rather than for
    truthiness. A test double standing in for Settings must not be able to turn
    prompt injection ON by accident, and a Settings that predates the knobs
    degrades to "no block" instead of raising mid-investigation.

    Cold-start inline refresh (building a dossier for an unseen host during the
    investigation that needs it) belongs to the caller: this function reports
    what the store holds, so it stays a pure read with a bounded cost.
    """
    settings = ctx.settings
    if getattr(settings, "dossier_enabled", False) is not True:
        return ""
    if getattr(settings, "dossier_context_enabled", False) is not True:
        return ""
    maker = ctx.db_sessionmaker
    if maker is None:
        # CLI / eval / direct callers run without a database. The dossier is
        # optional context, so its absence is not an error.
        return ""
    wanted = [(ip.strip(), label) for ip, label in ips.items() if ip and ip.strip()]
    if not wanted:
        return ""
    omitted = max(0, len(wanted) - max_hosts)
    wanted = wanted[:max_hosts]

    try:
        # Lazy so the renderer above stays importable — and unit-testable —
        # without the ORM and the database session in the import graph.
        from soc_ai.store import host_dossier as dossier_store  # noqa: PLC0415

        now = datetime.now(UTC)
        entries: list[ResolvedDossier] = []
        async with maker() as db:
            # ONE read for the whole block. The per-host `get_dossier` says in
            # its own words that it is the wrong shape here: this renders up to
            # `max_hosts` addresses on six LLM surfaces, so a loop is that many
            # round trips on the latency path of every investigation, both
            # chats, the hunt planner and the hunt console seed.
            stored = await dossier_store.get_dossiers(db, [ip for ip, _label in wanted])
            # Keyed on the STORE's canonical spelling, because that is what comes
            # back: `2001:db8:0:0:0:0:0:5` and `2001:db8::5` are one host and the
            # row carries the compressed form.
            by_key = {host.host_key: (host, rows) for host, rows in stored}
            for ip, _label in wanted:
                try:
                    key = dossier_store.normalize_host_key(ip)
                except ValueError:
                    # Not an address at all. No row can be keyed on it, and
                    # `host_key` is never empty, so this misses every time.
                    key = ""
                found = by_key.get(key)
                if found is None:
                    # Order and SPELLING are the caller's throughout: it decides
                    # which host leads, and the egress guard allocates one label
                    # per spelling, so an address re-rendered in canonical form
                    # would describe a host nobody asked about.
                    entries.append(unknown_dossier(ip))
                    continue
                resolved = resolve_dossier_from_settings(
                    found[0], found[1], now=now, settings=settings
                )
                # Re-spelled to the caller's address, not the row's. The resolver
                # takes `ip` off the stored row, which is CANONICAL — so a caller
                # that named `2001:db8:0:0:0:0:0:5` (the spelling
                # `internal_ips_in_text` hands over, because it returns what the
                # text said) got a line about `2001:db8::5`. Two costs, both real:
                # the label lookup in `format_host_dossier_block` is keyed on the
                # caller's string and silently missed, and the egress guard
                # allocates one label per spelling — so the block described IP_02
                # beside an objective about IP_01. This module's own docstring
                # already promises the caller's spelling; this is it keeping it.
                entries.append(dataclasses.replace(resolved, ip=ip))
    except Exception as exc:
        _LOGGER.warning("host_dossier_prompt_block failed: %s", exc)
        return ""

    if known_only:
        # NOT counted into `omitted`: these hosts were read and simply have no
        # record, which is a different statement from "dropped for space", and
        # `_omitted_line` tells the model to call `t_host_dossier` for the ones
        # it names — pointless advice for an address the sweep has never seen.
        entries = [entry for entry in entries if entry.found]

    # Same `now` the resolve pass used: staleness, relative labels and the
    # rebind window then all describe one instant, not three microseconds apart.
    block = format_host_dossier_block(entries, labels=dict(wanted), now=now, omitted=omitted)
    return f"\n\n{block}" if block else ""


# ---------------------------------------------------------------------------
# Which addresses does a piece of free text put in play?
# ---------------------------------------------------------------------------

# IPv4 dotted quad, ``\b``-anchored — the same shape
# ``narrative_grounding._IPV4`` uses, and anchored for the same reason. The word
# boundary is what makes this read the spellings the callers actually receive:
# OQL's own ``source.ip:10.1.2.3`` (the query language this product teaches the
# model to write), a URL like ``http://10.1.2.3/admin``, and a ``host:port``
# pair — ``\b`` holds after a ``:`` and before a ``/``, so none of them needs a
# case of its own. Octet ranges are left loose because ``ip_address`` below is
# the real validator; ``999.1.2.3`` fails there.
_IPV4_RE = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

# IPv6 literals, including the compressed and leading-``::`` forms. Bounded by
# lookarounds rather than ``\b`` (``:`` is not a word character, so ``\b`` would
# fire in the middle of an address) and deliberately loose about hextets: a MAC
# and a timestamp both match this shape and both fall out at ``ip_address``.
# Bracketed ``[fd00::1]:8443`` works because ``[`` and ``]`` are outside the
# class; the UNbracketed form is genuinely ambiguous (``fd00::1:8443`` is itself
# a valid address) and is deliberately not guessed at.
#
# The trailing lookaround excludes ``:`` but NOT ``.``, so a sentence-final
# period does not eat the address — the fully uncompressed spelling
# ``fd00:0:0:0:0:0:0:1.`` is one this codebase's own tests use.
_IPV6_RE = r"(?<![0-9A-Fa-f.:])[0-9A-Fa-f]{0,4}(?::[0-9A-Fa-f]{0,4}){2,7}(?![0-9A-Fa-f:])"

# One pass over the text so results come back in document order across both
# families. IPv4 leads: a dotted quad carries no colons, so the two branches
# cannot compete for the same span.
_ADDRESS_RE = re.compile(f"(?:{_IPV4_RE})|(?:{_IPV6_RE})")


def internal_ips_in_text(text: str, settings: Any) -> list[str]:
    """Distinct internal addresses named in *text*, in first-appearance order.

    The investigation pipeline reads its host set off the alert's typed fields.
    The other surfaces have no such fields — a hunt has an analyst's objective,
    a chat has a conversation — so this is how they answer "which addresses here
    could the dossier speak about". One definition ACROSS THOSE SURFACES: three
    prompt builders with three ideas of which addresses are ours is how one of
    them ends up describing the internet.

    "Internal" is ``settings.network_is_internal`` — ``internal_cidrs``
    membership, the operator's own definition of the network, and the same gate
    ``discovery._is_internal_ip`` applies when the census decides which hosts to
    build a dossier for at all. Anything outside it is dropped: an external
    address has no record and never will, so naming it would spend the block's
    budget on a line that only ever says "no record".

    It is NOT the only internal-address predicate in the codebase, and it is not
    meant to be. ``tools.online.is_internal_ip`` (behind
    ``first_internal_identifier``) calls anything not globally routable
    internal — CGNAT, benchmarking space, documentation ranges — plus
    ``internal_cidrs``, plus configured suffixes and hosts. That is an EGRESS
    SAFETY question, "may this leave the box", and it has to fail closed. This
    is a DOSSIER SCOPE question, "could the sweep hold a record of this", and
    widening it to match would put addresses in the block that no sweep can ever
    describe. Same word, two questions, and they should not be merged.

    The address is returned EXACTLY as the text spells it: the egress guard
    allocates one label per spelling, and a dossier line about ``IP_02`` beside
    an objective about ``IP_01`` describes a host nobody asked about.

    A CIDR is skipped — ``192.168.10.0/24`` names a range, and rendering its
    network address as a machine is a "no dossier" line about something that is
    not one. The test is ``/`` followed by a DIGIT, not a bare ``/``: a URL path
    (``http://10.1.2.3/admin``) is an analyst naming the box they are asking
    about, and rejecting it on the slash alone loses the host entirely.
    """
    haystack = text or ""
    found: dict[str, None] = {}
    for match in _ADDRESS_RE.finditer(haystack):
        if haystack[match.end() : match.end() + 1] == "/" and (
            haystack[match.end() + 1 : match.end() + 2].isdigit()
        ):
            continue  # a CIDR prefix length, not a URL path
        candidate = _parsed_address(match.group())
        if candidate is None:
            continue
        if settings.network_is_internal(candidate):
            found.setdefault(candidate, None)
    return list(found)


def _parsed_address(token: str) -> str | None:
    """*token* if it is a real address, else ``None``.

    The one retry covers OQL written against an IPv6 host. A leading ``:`` is
    ambiguous by construction — it is either the field separator in
    ``source.ip:fd00::1`` or part of a ``::`` compression — and the IPv6 pattern
    cannot tell them apart without also matching a stray colon mid-address. So
    the greedy match is tried first, and only if it fails is a SINGLE leading
    colon dropped and the rest re-parsed. ``::1`` never reaches the retry
    because it parses on the first attempt.
    """
    try:
        ip_address(token)
    except ValueError:
        pass
    else:
        return token
    if token.startswith(":") and not token.startswith("::"):
        stripped = token[1:]
        try:
            ip_address(stripped)
        except ValueError:
            return None
        return stripped
    return None


# ---------------------------------------------------------------------------
# Assembly + budget
# ---------------------------------------------------------------------------


def _assemble(host_blocks: list[str]) -> str:
    return "\n".join([HEADING, "", _INTRO, "", *host_blocks])


def _fit_host(entry: ResolvedDossier, label: str | None, *, floor: int, now: datetime) -> str:
    """Render one host at the least-truncated level that fits its own budget."""
    text = ""
    for level in range(floor, _L_NO_DETAIL + 1):
        text = "\n".join(_host_lines(entry, label, level=level, now=now))
        if estimate_tokens(text) <= MAX_TOKENS_PER_HOST:
            return text
    return text


def _drop_hosts(rendered: list[str], *, extra: int = 0) -> str:
    """Keep the leading hosts that fit, naming the count of those that did not.

    *extra* is the caller's own pre-read truncation, added to whatever the
    budget drops here so the block states ONE total.
    """
    for kept in range(len(rendered) - 1, 0, -1):
        omitted = len(rendered) - kept + extra
        block = _assemble([*rendered[:kept], _omitted_line(omitted)])
        if estimate_tokens(block) <= MAX_TOKENS_TOTAL:
            return block
    return _assemble([rendered[0], _omitted_line(len(rendered) - 1 + extra)])


def _omitted_line(count: int) -> str:
    plural = "host" if count == 1 else "hosts"
    return f"- (+{count} more {plural} omitted for space — call `t_host_dossier` for them)"


# ---------------------------------------------------------------------------
# One host
# ---------------------------------------------------------------------------


def _host_lines(
    entry: ResolvedDossier, label: str | None, *, level: int, now: datetime
) -> list[str]:
    head = f"{entry.ip} ({label})" if label else entry.ip
    if not entry.found:
        return [
            f"- {head} — no dossier: the network sweep has no record of this address "
            "(external, or never observed). That is not evidence it is benign."
        ]

    lines = [f"- {head} — role: {_role_text(entry, level=level)}"]
    lines.extend(_identity_lines(entry, level=level))
    lines.extend(_operator_lines(entry, level=level))
    rebound_at = entry.identity_rebound_at
    if rebound_at is not None and _rebind_is_recent(rebound_at, now=now):
        # Never dropped by the truncation ladder while it applies at all: an
        # override may describe a machine that has moved on, and a reader
        # weighing one has to know that before trusting it.
        lines.append(
            "  note: a different machine appears to hold this address since "
            f"{_date(rebound_at)} — any operator value set before "
            "then may no longer apply."
        )
    if level < _L_NO_BASELINE and (baseline := _baseline_text(entry)):
        lines.append(f"  baseline: {baseline}")
    if level < _L_NO_SEEN and (seen := _seen_text(entry, now=now)):
        lines.append(f"  {seen}")
    return lines


def _rebind_is_recent(rebound_at: datetime, *, now: datetime) -> bool:
    """Is the "a different machine holds this address" tripwire still worth saying?

    Time-bounded because ``identity_rebound_at`` is stamped and never cleared:
    rendered on presence alone, the note is PERMANENT once written, so a host
    that changed hands in June carries the warning on every alert for the rest
    of the deployment's life — and a note that is always there is a note nobody
    reads, which costs the block the credibility the case it was written for
    depends on.

    :data:`REBIND_NOTE_WINDOW_DAYS` past the rebind, the note also has nothing
    left to undermine: every inferred fact beside it was re-derived from
    telemetry the CURRENT occupant produced, and an override that survived a
    month of sweeps is one the operator has had the prod (and the dossier
    screen's conflict row) in front of them about. The tripwire itself is not
    lost — ``t_host_dossier`` and the API still report the raw timestamp.
    """
    return _aware(now) - _aware(rebound_at) <= timedelta(days=REBIND_NOTE_WINDOW_DAYS)


def _role_text(entry: ResolvedDossier, *, level: int) -> str:
    """The headline. Always rendered, unknown or not — role is why we are here."""
    field = entry.fields.get("role")
    if field is None:
        return "unknown [not evaluated yet]"
    if not field.is_known or field.value is None:
        return f"unknown [{_unknown_text(field)}]"
    return f"{_clip(field.value)} {_provenance(field, level=level)}"


def _identity_lines(entry: ResolvedDossier, *, level: int) -> list[str]:
    """Hostname, OS and domain — only the ones that resolved.

    Rendering all twelve fields with their unknown reasons would cost more than
    the whole block is worth; the tool carries the full record, and the header
    already tells the model how to reach it.
    """
    lines: list[str] = []
    if (hostname := _known(entry, "hostname")) is not None:
        lines.append(f"  hostname: {_clip(hostname.value)} {_provenance(hostname, level=level)}")
    if (os_family := _known(entry, "os_family")) is not None:
        text = str(os_family.value)
        os_detail = _known(entry, "os_detail")
        if level < _L_NO_DETAIL and os_detail is not None and os_detail.value:
            text = f"{text}/{os_detail.value}"
        lines.append(f"  os: {_clip(text)} {_provenance(os_family, level=level)}")
    if (domain := _known(entry, "domain_membership")) is not None:
        lines.append(f"  domain: {_clip(domain.value)} {_provenance(domain, level=level)}")
    return lines


def _operator_lines(entry: ResolvedDossier, *, level: int) -> list[str]:
    """Criticality and policy. Never truncated away — this is the site's own
    judgement about the asset, and the only dossier content no amount of
    telemetry could have produced."""
    lines: list[str] = []
    if (crit := _known(entry, "criticality")) is not None:
        lines.append(f"  criticality: {_clip(crit.value)} {_provenance(crit, level=level)}")
    if (policy := _known(entry, "policy_notes")) is not None:
        lines.append(f"  policy: {_clip(policy.value)} {_provenance(policy, level=level)}")
    return lines


def _baseline_text(entry: ResolvedDossier) -> str:
    """What the host normally does — the line that turns "host did X" into "host
    did X, which it has never done before"."""
    bits: list[str] = []
    if services := _port_list(_json_value(entry, "services_offered")):
        shown, total = services
        more = f" (+{total - len(shown)} more)" if total > len(shown) else ""
        bits.append("serves " + ", ".join(shown) + more)
    if (mgmt := _known(entry, "management_plane")) is not None and mgmt.value == "yes":
        mgmt_ports = _port_list(mgmt.value_json)
        if mgmt_ports is None:
            bits.append("exposes a management plane")
        else:
            bits.append("management plane on " + ", ".join(mgmt_ports[0]))
    activity = _json_value(entry, "activity_profile")
    if isinstance(activity, dict):
        bits.extend(_activity_bits(activity))
    if (static := _known(entry, "is_static_addressed")) is not None:
        bits.append("statically addressed" if static.value == "yes" else "DHCP-leased")
    return "; ".join(bits)


def _activity_bits(activity: dict[str, Any]) -> list[str]:
    bits: list[str] = []
    initiates = activity.get("initiates_remote_access")
    if initiates is True:
        ports = _port_list(activity.get("remote_access_ports"))
        detail = "" if ports is None else " on " + ", ".join(ports[0])
        bits.append(f"initiates outbound remote access{detail}")
    elif initiates is False:
        bits.append(
            f"has not initiated outbound remote access ({_REMOTE_ACCESS_LABEL}) "
            "in the observed window"
        )
    hours = activity.get("busiest_hours")
    if isinstance(hours, list) and hours:
        labels = [f"{hour:02d}:00" for hour in (_as_int(h) for h in hours[:3]) if hour is not None]
        if labels:
            bits.append("busiest " + ", ".join(labels) + " UTC")
    return bits


def _seen_text(entry: ResolvedDossier, *, now: datetime) -> str:
    bits: list[str] = []
    if entry.first_seen is not None:
        bits.append(f"first seen {_date(entry.first_seen)}")
    if entry.last_seen is not None:
        bits.append(f"last seen {_ago(entry.last_seen, now=now)}")
    if entry.event_count:
        bits.append(f"{entry.event_count:,} events in the last sweep window")
    return " · ".join(bits)


# ---------------------------------------------------------------------------
# Field rendering
# ---------------------------------------------------------------------------


def _known(entry: ResolvedDossier, field: str) -> ResolvedField | None:
    """The field if it resolved to something assertable, else ``None``."""
    resolved = entry.fields.get(field)
    if resolved is None or not resolved.is_known or resolved.value is None:
        return None
    return resolved


def _json_value(entry: ResolvedDossier, field: str) -> Any | None:
    resolved = entry.fields.get(field)
    if resolved is None or not resolved.is_known:
        return None
    return resolved.value_json


def _provenance(field: ResolvedField, *, level: int) -> str:
    """``[operator · analyst · 2026-08-01]`` or ``[inferred · strong: <evidence>]``.

    The operator tag names the human and the date because "authoritative" is a
    claim a reader is entitled to check; the inferred tag names the strength
    because a weak inference and a strong one should not argue with equal force.
    """
    if field.source == OPERATOR_SOURCE:
        bits = ["operator"]
        if field.operator_actor:
            bits.append(field.operator_actor)
        if field.operator_set_at is not None:
            bits.append(_date(field.operator_set_at))
        return f"[{' · '.join(bits)}]"
    if level < _L_NO_EVIDENCE and (evidence := _evidence_text(field)):
        return f"[inferred · {field.strength}: {evidence}]"
    return f"[inferred · {field.strength}]"


def _evidence_text(field: ResolvedField) -> str:
    """The winning source's own evidence strings, plus any family disagreement.

    Evidence is stored keyed BY SOURCE so a weaker signal that lost the merge
    survives beside the one that won; the block shows the winner's, and shows a
    recorded ``conflict`` because a host whose banner and whose traffic tell
    different stories is exactly the case worth reading.
    """
    entry = field.evidence.get(field.source or "")
    if not isinstance(entry, dict):
        return ""
    strings = entry.get("strings")
    text = ""
    if isinstance(strings, list):
        text = "; ".join(str(item) for item in strings[:2] if item)
    conflict = entry.get("conflict")
    if conflict:
        text = f"{text} — conflict: {conflict}" if text else f"conflict: {conflict}"
    return _clip(text, _EVIDENCE_CHARS)


def _unknown_text(field: ResolvedField) -> str:
    """Why a field did not resolve. Three reasons, three different answers."""
    if field.reason == "stale":
        if field.last_run_at is None:
            return "stale — never confirmed by a build"
        return f"stale — not re-confirmed since {_date(field.last_run_at)}"
    if field.reason == "low_confidence":
        return "signal too weak to assert — below the confidence floor"
    if field.last_run_at is None:
        return "not evaluated yet — no build has looked"
    return "no signal in the observed window"


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _clip(value: str | None, limit: int = _VALUE_CHARS) -> str:
    """Bound one rendered value, marking the cut.

    Applied to every value including the ones truncation never drops: keeping a
    field is a promise about which facts survive, not a licence for one field to
    consume the prompt.
    """
    text = " ".join(str(value or "").split())
    if len(text) <= limit:
        return text
    return text[: limit - 1].rstrip() + "…"


def _port_list(value: Any) -> tuple[list[str], int] | None:
    """``[{"port": 8006, "proto": "tcp"}, ...]`` or ``[22, 443]`` -> ``tcp/8006``.

    Both shapes come out of a JSON column, so anything unrecognised is skipped
    rather than rendered as its repr.
    """
    if not isinstance(value, list) or not value:
        return None
    ports: list[str] = []
    for item in value:
        if len(ports) >= 6:
            break
        if isinstance(item, dict):
            port = _as_int(item.get("port"))
            proto = str(item.get("proto") or "tcp")
        else:
            port, proto = _as_int(item), "tcp"
        if port is not None:
            ports.append(f"{proto}/{port}")
    if not ports:
        return None
    return ports, len(value)


def _as_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _date(value: datetime) -> str:
    return value.strftime("%Y-%m-%d")


def _aware(value: datetime) -> datetime:
    """UTC-aware view of a timestamp. Stored ones are naive UTC; a clock is not.

    Subtracting a naive datetime from an aware one raises, and this renderer
    mixes both on every host — one arm of every comparison comes out of the
    database, the other from the caller.
    """
    return value if value.tzinfo is not None else value.replace(tzinfo=UTC)


def _ago(value: datetime, *, now: datetime) -> str:
    """Short relative label, measured against the render's clock."""
    secs = (_aware(now) - _aware(value)).total_seconds()
    if secs < 60:
        return "just now"
    if secs < 3600:
        return f"{int(secs // 60)}m ago"
    if secs < 86400:
        return f"{int(secs // 3600)}h ago"
    return f"{int(secs // 86400)}d ago"


__all__ = [
    "HEADING",
    "MAX_PROMPT_HOSTS",
    "MAX_TOKENS_PER_HOST",
    "MAX_TOKENS_TOTAL",
    "REBIND_NOTE_WINDOW_DAYS",
    "format_host_dossier_block",
    "host_dossier_prompt_block",
    "internal_ips_in_text",
]
