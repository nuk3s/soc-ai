"""Tests for the dossier prompt block — how an asset record reaches the model.

The block is the only place the dossier gets to change a verdict without the
agent asking for it, so three properties are pinned here:

* it is framed as **system-inferred context, not evidence**. An inferred role
  that reads as a citable fact is a laundering channel: telemetry a hostile host
  can influence (the hostname it announces over DHCP) would become the thing a
  verdict rests on. The heading says so and points at ``t_host_dossier`` as the
  citable route;
* absence is stated out loud beside a host that IS described. Silently omitting
  the second host reads as "nothing notable about that one", which is the exact
  failure the dossier exists to fix;
* it fits a budget. The block is prepended to a prompt that already carries the
  enriched alert; an operator who pastes a page of policy into ``policy_notes``
  must not be able to push the correlation signal out of the model's window.
  Truncation drops the descriptive tail and keeps role, criticality and policy —
  the three fields that actually move a verdict.

Rendering is tested through ``format_host_dossier_block`` on hand-built
:class:`ResolvedDossier` values (pure, no DB) and the async wrapper is tested
with the store call monkeypatched, because the wrapper's contract is "never
raises, '' on any failure" and that is only provable by making the store fail.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from ipaddress import ip_network
from types import SimpleNamespace
from typing import Any

import pytest
from soc_ai.agent.context_budget import estimate_tokens
from soc_ai.config import Settings
from soc_ai.dossier.prompt import (
    MAX_TOKENS_PER_HOST,
    MAX_TOKENS_TOTAL,
    REBIND_NOTE_WINDOW_DAYS,
    format_host_dossier_block,
    host_dossier_prompt_block,
    internal_ips_in_text,
)
from soc_ai.dossier.resolve import ResolvedDossier, ResolvedField
from soc_ai.dossier.types import DOSSIER_FIELDS
from soc_ai.store.models import HostDossier, HostDossierField

NOW = datetime(2026, 8, 6, 12, 0, 0, tzinfo=UTC)


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def _known(
    field: str,
    value: str,
    *,
    source: str = "behaviour",
    confidence: float = 0.9,
    strength: str = "strong",
    evidence: str | None = None,
    value_json: Any | None = None,
    actor: str | None = None,
) -> ResolvedField:
    """A field that resolved, with its evidence keyed by source (store shape)."""
    return ResolvedField(
        field=field,
        value=value,
        value_json=value_json,
        source=source,
        confidence=confidence,
        strength=strength,  # type: ignore[arg-type]
        reason=None,
        evidence={source: {"strings": [evidence]}} if evidence else {},
        observed_at=NOW - timedelta(minutes=3),
        first_seen=NOW - timedelta(days=65),
        last_run_at=NOW - timedelta(hours=1),
        operator_actor=actor,
        operator_set_at=NOW - timedelta(days=5) if actor else None,
    )


def _unknown(field: str, reason: str, *, last_run_at: datetime | None = None) -> ResolvedField:
    return ResolvedField(
        field=field,
        reason=reason,  # type: ignore[arg-type]
        last_run_at=last_run_at,
    )


def _dossier(ip: str = "192.168.10.202", **fields: ResolvedField) -> ResolvedDossier:
    """A found host; every field not named resolves to ``no_signal``."""
    resolved = {name: ResolvedField(field=name) for name in DOSSIER_FIELDS}
    resolved.update(fields)
    return ResolvedDossier(
        ip=ip,
        found=True,
        fields=resolved,
        first_seen=NOW - timedelta(days=65),
        last_seen=NOW - timedelta(minutes=3),
        last_built_at=NOW - timedelta(hours=1),
        event_count=3412,
    )


def _absent(ip: str = "8.8.8.8") -> ResolvedDossier:
    return ResolvedDossier(
        ip=ip, found=False, fields={name: ResolvedField(field=name) for name in DOSSIER_FIELDS}
    )


def _hypervisor(ip: str = "192.168.10.202") -> ResolvedDossier:
    return _dossier(
        ip,
        role=_known(
            "role",
            "hypervisor",
            evidence=(
                "responds on tcp/8006, tcp/8007, tcp/3128 — 3,412 zeek.conn records "
                "from 4 distinct peers across 19 hours (from behaviour)"
            ),
        ),
        hostname=_known("hostname", "pve01", source="banner", evidence="pve01 (from dhcp)"),
        os_family=_known(
            "os_family", "linux", source="banner", evidence="OpenSSH_9.6p1 Debian-3 (from ssh)"
        ),
        os_detail=_known("os_detail", "debian", source="banner"),
        criticality=_known(
            "criticality", "high", source="operator", confidence=1.0, actor="analyst"
        ),
        policy_notes=_known(
            "policy_notes",
            "no interactive SSH; API-token access only",
            source="operator",
            confidence=1.0,
            actor="analyst",
        ),
        services_offered=_known(
            "services_offered",
            "5 services",
            value_json=[
                {"port": 22, "proto": "tcp", "count": 120, "service": "ssh"},
                {"port": 443, "proto": "tcp", "count": 980, "service": "ssl"},
                {"port": 8006, "proto": "tcp", "count": 2100, "service": None},
            ],
        ),
        activity_profile=_known(
            "activity_profile",
            "profiled",
            value_json={
                "busiest_hours": [9, 10, 14],
                "initiates_remote_access": False,
                "remote_access_ports": [],
            },
        ),
    )


def _host_chunks(block: str) -> list[str]:
    """Split a rendered block into its per-host chunks.

    Pins the render contract the budget depends on: one ``- `` line per host,
    continuation lines indented two spaces.
    """
    chunks: list[str] = []
    for line in block.splitlines():
        if line.startswith("- "):
            chunks.append(line)
        elif chunks and line.startswith("  "):
            chunks[-1] += "\n" + line
    return chunks


# ---------------------------------------------------------------------------
# Framing: system-inferred, NOT evidence
# ---------------------------------------------------------------------------


def test_empty_input_renders_nothing() -> None:
    """Callers append unconditionally, so "nothing to say" must be ''."""
    assert format_host_dossier_block([]) == ""


def test_block_is_framed_as_context_and_not_as_evidence() -> None:
    block = format_host_dossier_block([_hypervisor()])
    head = block.split("\n\n", 1)[0]
    assert head.startswith("## Host dossier")
    assert "NOT evidence" in head
    # The citable route has to be named, or "don't cite this" is a dead end.
    assert "t_host_dossier" in block
    assert "Operator-set values are authoritative" in block


def test_operator_values_render_with_their_actor_and_date() -> None:
    block = format_host_dossier_block([_hypervisor()])
    assert "criticality: high [operator · analyst · 2026-08-01]" in block
    assert (
        "policy: no interactive SSH; API-token access only [operator · analyst · 2026-08-01]"
        in (block)
    )


def test_inferred_role_carries_strength_and_its_evidence() -> None:
    block = format_host_dossier_block([_hypervisor()])
    assert "role: hypervisor [inferred · strong:" in block
    assert "tcp/8006" in block


def test_unknown_role_states_why_rather_than_going_quiet() -> None:
    """Three unknowns, three different answers — an agent handed silence for all
    three reads every one of them as "nothing notable"."""
    stale = format_host_dossier_block(
        [_dossier(role=_unknown("role", "stale", last_run_at=NOW - timedelta(days=9)))]
    )
    weak = format_host_dossier_block([_dossier(role=_unknown("role", "low_confidence"))])
    silent = format_host_dossier_block(
        [_dossier(role=_unknown("role", "no_signal", last_run_at=NOW - timedelta(hours=2)))]
    )
    assert "stale" in stale
    assert "2026-07-28" in stale  # names WHEN it was last confirmed
    assert "role: unknown" in weak
    assert "confidence" in weak
    assert "stale" not in weak
    assert "role: unknown" in silent
    assert "stale" not in silent


def test_absent_host_is_stated_beside_a_described_one() -> None:
    """The failure this feature exists to fix: a silently omitted host reads as
    'nothing notable about that one'."""
    block = format_host_dossier_block(
        [_hypervisor(), _absent("8.8.8.8")],
        labels={"192.168.10.202": "source", "8.8.8.8": "destination"},
    )
    assert "192.168.10.202 (source)" in block
    assert "8.8.8.8 (destination)" in block
    assert "no dossier" in block
    chunks = _host_chunks(block)
    assert len(chunks) == 2


def test_no_host_has_a_record_renders_nothing() -> None:
    """A block whose only content is "we have no record of either host" is noise
    on every alert of a deployment that has not swept yet, and it trains the
    model to skip the section that will matter once it has. Absence is stated
    only beside a host that IS described, where the contrast is the point."""
    assert format_host_dossier_block([_absent("8.8.8.8"), _absent("1.1.1.1")]) == ""


def test_baseline_states_what_the_host_has_never_done() -> None:
    """The line that turns "host did X" into "host did X, which it never does"."""
    block = format_host_dossier_block([_hypervisor()])
    assert "baseline:" in block
    assert "tcp/8006" in block
    assert "remote access" in block


def test_baseline_reads_both_json_port_shapes() -> None:
    """``management_plane`` stores bare ports and ``services_offered`` stores
    dicts; both come out of a JSON column, and a shape the renderer does not
    understand would put a Python repr into the prompt."""
    entry = _dossier(
        management_plane=_known("management_plane", "yes", value_json=[22, 8006]),
        is_static_addressed=_known("is_static_addressed", "yes"),
        activity_profile=_known(
            "activity_profile",
            "profiled",
            value_json={
                "initiates_remote_access": True,
                "remote_access_ports": [22, "not-a-port"],
                "busiest_hours": ["3"],
            },
        ),
    )
    block = format_host_dossier_block([entry])
    assert "management plane on tcp/22, tcp/8006" in block
    assert "initiates outbound remote access on tcp/22" in block
    assert "busiest 03:00 UTC" in block
    assert "statically addressed" in block
    assert "not-a-port" not in block


def test_recorded_family_disagreement_survives_into_the_block() -> None:
    """A host whose banner and whose traffic tell different stories is the case
    most worth reading, so the conflict rides along with the evidence."""
    field = _known("os_family", "linux", source="banner", evidence="OpenSSH_9.6p1 Debian-3")
    conflicted = ResolvedField(
        **{
            **field.__dict__,
            "evidence": {
                "banner": {
                    "strings": ["OpenSSH_9.6p1 Debian-3"],
                    "conflict": "OS family disagreement: banner=linux vs user-agent=windows",
                }
            },
        }
    )
    block = format_host_dossier_block([_dossier(os_family=conflicted)])
    assert "conflict: OS family disagreement" in block


def test_a_field_no_build_ever_evaluated_says_so() -> None:
    """ "Nobody has looked" is not "we looked and found nothing"."""
    block = format_host_dossier_block([_dossier(role=_unknown("role", "no_signal"))])
    assert "not evaluated yet" in block


def _rebound(at: datetime) -> ResolvedDossier:
    entry = _hypervisor()
    return ResolvedDossier(
        ip=entry.ip,
        found=True,
        fields=entry.fields,
        first_seen=entry.first_seen,
        last_seen=entry.last_seen,
        identity_rebound_at=at,
    )


def test_identity_rebind_is_reported_beside_the_override() -> None:
    """An override may describe a machine that has moved on."""
    block = format_host_dossier_block([_rebound(NOW - timedelta(days=1))], now=NOW)
    assert "different machine" in block


def test_a_long_past_identity_rebind_stops_being_reported() -> None:
    """``identity_rebound_at`` is stamped and never cleared, so an unbounded note
    is permanent once written: a host that changed hands in June carries the
    warning on every alert forever, and a note that is always there is a note
    nobody reads. Past the observation window the rebind predates every fact in
    the block, and those facts already describe whatever holds the address now."""
    block = format_host_dossier_block(
        [_rebound(NOW - timedelta(days=REBIND_NOTE_WINDOW_DAYS + 1))], now=NOW
    )
    assert "different machine" not in block
    # The host itself is still described — only the stale tripwire is dropped.
    assert "role: hypervisor" in block


def test_relative_times_are_measured_against_the_supplied_clock() -> None:
    """``now`` is a parameter so the block is deterministic — a renderer reading
    the wall clock cannot be tested for anything time-bounded, including the
    rebind window above."""
    block = format_host_dossier_block([_hypervisor()], now=NOW)
    assert "last seen 3m ago" in block


# ---------------------------------------------------------------------------
# Budget
# ---------------------------------------------------------------------------


def _fat(ip: str) -> ResolvedDossier:
    """A host whose every renderable field is pathologically long."""
    entry = _hypervisor(ip)
    fields = dict(entry.fields)
    fields["role"] = _known("role", "hypervisor", evidence="responds on tcp/8006 " * 200)
    fields["policy_notes"] = _known(
        "policy_notes", "no interactive SSH; " * 200, source="operator", confidence=1.0
    )
    fields["hostname"] = _known("hostname", "pve01", source="banner", evidence="pve01 " * 200)
    return ResolvedDossier(
        ip=ip,
        found=True,
        fields=fields,
        first_seen=entry.first_seen,
        last_seen=entry.last_seen,
        event_count=entry.event_count,
    )


def test_per_host_budget_holds_for_a_pathological_host() -> None:
    block = format_host_dossier_block([_fat("192.168.10.202")])
    for chunk in _host_chunks(block):
        assert estimate_tokens(chunk) <= MAX_TOKENS_PER_HOST, chunk


def test_total_budget_holds_across_many_hosts() -> None:
    entries = [_fat(f"192.168.10.{n}") for n in range(20, 26)]
    block = format_host_dossier_block(entries)
    assert estimate_tokens(block) <= MAX_TOKENS_TOTAL


def test_truncation_keeps_role_criticality_and_policy() -> None:
    """Drop the descriptive tail, never the three fields that change a verdict."""
    block = format_host_dossier_block([_fat("192.168.10.202"), _fat("192.168.10.203")])
    for chunk in _host_chunks(block):
        assert "role: hypervisor" in chunk
        assert "criticality: high" in chunk
        assert "policy: no interactive SSH" in chunk
    # The tail is what paid for it.
    assert "baseline:" not in block


def test_dropped_hosts_are_named_not_silently_omitted() -> None:
    entries = [_fat(f"192.168.10.{n}") for n in range(20, 40)]
    block = format_host_dossier_block(entries)
    assert estimate_tokens(block) <= MAX_TOKENS_TOTAL
    assert "more host" in block  # "(+N more hosts omitted …)"


def test_a_caller_that_pre_dropped_hosts_is_told_about_in_one_number() -> None:
    """Two truncations, ONE count.

    A caller bounded at :data:`MAX_PROMPT_HOSTS` drops hosts before they are
    ever read, and the budget ladder then drops more. Reporting only the second
    number would understate the omission — and the whole point of the trailing
    line is that a shortened list never reads as a complete one. ``omitted``
    carries the caller's remainder into the same count.
    """
    entries = [_fat(f"192.168.10.{n}") for n in range(20, 40)]
    pre_dropped = 3

    block = format_host_dossier_block(entries, omitted=pre_dropped)

    assert estimate_tokens(block) <= MAX_TOKENS_TOTAL
    described = [chunk for chunk in _host_chunks(block) if "more host" not in chunk]
    reported = int(re.search(r"\(\+(\d+) more host", block).group(1))  # type: ignore[union-attr]
    assert reported == len(entries) - len(described) + pre_dropped


def test_a_pre_dropped_remainder_is_stated_even_when_everything_fits() -> None:
    """The budget ladder has nothing to say here — the caller's cap does.

    Without this the common case is the silent one: eight hosts render
    comfortably inside the budget and the ninth simply never existed.
    """
    block = format_host_dossier_block([_hypervisor()], omitted=4)

    assert "(+4 more hosts omitted" in block
    assert estimate_tokens(block) <= MAX_TOKENS_TOTAL


# ---------------------------------------------------------------------------
# The async wrapper: never raises, '\n\n'-prefixed
# ---------------------------------------------------------------------------


class _FakeSession:
    async def __aenter__(self) -> _FakeSession:
        return self

    async def __aexit__(self, *exc: object) -> bool:
        return False


class _FakeSessionmaker:
    def __init__(self) -> None:
        self.opened = 0

    def __call__(self) -> _FakeSession:
        self.opened += 1
        return _FakeSession()


def _ctx(*, enabled: bool = True, context_enabled: bool = True, db: bool = True) -> Any:
    return SimpleNamespace(
        settings=SimpleNamespace(
            dossier_enabled=enabled,
            dossier_context_enabled=context_enabled,
            dossier_min_confidence=0.6,
            dossier_staleness_hours=72,
        ),
        db_sessionmaker=_FakeSessionmaker() if db else None,
    )


def _stored_hypervisor() -> tuple[HostDossier, list[HostDossierField]]:
    """Store rows for the ASYNC block, stamped against the REAL clock.

    Deliberately not :data:`NOW`. ``host_dossier_prompt_block`` resolves with
    ``datetime.now``, and the resolver withholds a field whose
    ``inferred_last_run_at`` is outside the staleness window — so rows pinned to
    a fixed past date keep passing until real time drifts past that window, then
    fail forever. That is exactly what happened: these rows sat at 2026-08-06 and
    the suite went red on 2026-08-09, three days and one staleness window later,
    with no code change. The pure-render tests keep using ``NOW`` because they
    pass it in explicitly (``format_host_dossier_block(..., now=NOW)``) and are
    deterministic for that reason.
    """
    real_now = datetime.now(UTC).replace(tzinfo=None)
    rows = [
        HostDossierField(
            field="role",
            inferred_value="hypervisor",
            inferred_confidence=0.9,
            inferred_source="behaviour",
            inferred_last_run_at=real_now - timedelta(hours=1),
            inferred_evidence={"behaviour": {"strings": ["responds on tcp/8006 (from behaviour)"]}},
        )
    ]
    host = HostDossier(
        host_key="192.168.10.202",
        ip="192.168.10.202",
        first_seen=real_now - timedelta(days=65),
        last_seen=real_now - timedelta(minutes=3),
        event_count=3412,
    )
    return host, rows


def _stored_batch(*known: str) -> Any:
    """``get_dossiers`` as a fake, with its real contract.

    Rows come back only for the addresses that HAVE one — an unknown address is
    absent from the result, never a placeholder in it — and in the store's own
    order, which is the row order and not the caller's.
    """

    async def _get_dossiers(
        db: object, ips: list[str]
    ) -> list[tuple[HostDossier, list[HostDossierField]]]:
        return [_stored_hypervisor() for ip in ips if ip in known]

    return _get_dossiers


@pytest.mark.asyncio
async def test_prompt_block_prefixes_a_blank_line(monkeypatch: pytest.MonkeyPatch) -> None:
    from soc_ai.store import host_dossier as store

    monkeypatch.setattr(store, "get_dossiers", _stored_batch("192.168.10.202"))
    block = await host_dossier_prompt_block(
        {"192.168.10.202": "source", "8.8.8.8": "destination"}, ctx=_ctx()
    )
    assert block.startswith("\n\n## Host dossier")
    assert "role: hypervisor" in block
    assert "8.8.8.8 (destination)" in block


@pytest.mark.asyncio
async def test_the_block_reads_every_host_in_ONE_batch(monkeypatch: pytest.MonkeyPatch) -> None:
    """One store read for the block, however many addresses are in play.

    The block renders up to :data:`MAX_PROMPT_HOSTS` hosts and sits on six LLM
    surfaces — investigations, both chats, the hunt planner, the hunt console
    seed. A loop over the per-host lookup is that many round trips per prompt,
    on the latency path of every one of them, and the batch read exists (its own
    docstring says the per-host shape "is the wrong shape" for exactly this).
    """
    from soc_ai.store import host_dossier as store

    batches: list[list[str]] = []

    async def _get_many(
        db: object, ips: list[str]
    ) -> list[tuple[HostDossier, list[HostDossierField]]]:
        batches.append(list(ips))
        return [_stored_hypervisor()] if "192.168.10.202" in ips else []

    async def _per_host(db: object, ip: str) -> None:
        raise AssertionError("the block must not loop the per-host lookup")

    monkeypatch.setattr(store, "get_dossiers", _get_many)
    monkeypatch.setattr(store, "get_dossier", _per_host)

    wanted = {f"192.168.10.{n}": "related event" for n in range(200, 208)}
    wanted["192.168.10.202"] = "source"

    block = await host_dossier_prompt_block(wanted, ctx=_ctx())

    assert len(batches) == 1, batches
    assert batches[0] == list(wanted)
    assert "role: hypervisor" in block


@pytest.mark.asyncio
async def test_the_batch_read_keeps_the_callers_order_and_its_own_spelling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A batch read comes back keyed on the STORE's canonical address, not on the
    caller's spelling, and in whatever order the rows arrived. The block's order
    is the caller's — it decides which host leads — and its labels are keyed on
    the caller's text, so a host that came back under a different spelling of the
    same address must still find its label and its place.
    """
    from soc_ai.store import host_dossier as store

    async def _get_many(
        db: object, ips: list[str]
    ) -> list[tuple[HostDossier, list[HostDossierField]]]:
        # Reversed, and the v6 address in its canonical (compressed) form —
        # both of which a real store read can hand back.
        host, rows = _stored_hypervisor()
        v6 = HostDossier(host_key="2001:db8::5", ip="2001:db8::5", event_count=7)
        return [(v6, []), (host, rows)]

    monkeypatch.setattr(store, "get_dossiers", _get_many)

    block = await host_dossier_prompt_block(
        {"192.168.10.202": "source", "2001:db8:0:0:0:0:0:5": "destination"}, ctx=_ctx()
    )

    chunks = _host_chunks(block)
    assert "192.168.10.202 (source)" in chunks[0], chunks
    # Rendered under the spelling the CALLER used: the egress guard allocates one
    # label per spelling, so the block must not introduce a second one.
    assert "2001:db8:0:0:0:0:0:5 (destination)" in block


@pytest.mark.asyncio
async def test_prompt_block_off_when_context_switch_is_off(monkeypatch: pytest.MonkeyPatch) -> None:
    from soc_ai.store import host_dossier as store

    async def _boom(db: object, ips: list[str]) -> None:
        raise AssertionError("must not query the store with the switch off")

    monkeypatch.setattr(store, "get_dossiers", _boom)
    assert (
        await host_dossier_prompt_block({"192.168.10.202": "source"}, ctx=_ctx(enabled=False)) == ""
    )
    assert (
        await host_dossier_prompt_block(
            {"192.168.10.202": "source"}, ctx=_ctx(context_enabled=False)
        )
        == ""
    )


@pytest.mark.asyncio
async def test_prompt_block_off_without_a_database() -> None:
    """CLI / eval callers have no sessionmaker; the block is optional, not fatal."""
    assert await host_dossier_prompt_block({"192.168.10.202": "source"}, ctx=_ctx(db=False)) == ""


@pytest.mark.asyncio
async def test_prompt_block_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """A dossier read that fails must cost the investigation nothing."""
    from soc_ai.store import host_dossier as store

    async def _boom(db: object, ips: list[str]) -> None:
        raise RuntimeError("no such table: host_dossier")

    monkeypatch.setattr(store, "get_dossiers", _boom)
    assert await host_dossier_prompt_block({"192.168.10.202": "source"}, ctx=_ctx()) == ""


@pytest.mark.asyncio
async def test_prompt_block_skips_blank_ips(monkeypatch: pytest.MonkeyPatch) -> None:
    from soc_ai.store import host_dossier as store

    seen: list[str] = []

    async def _get_dossiers(
        db: object, ips: list[str]
    ) -> list[tuple[HostDossier, list[HostDossierField]]]:
        seen.extend(ips)
        return [_stored_hypervisor()]

    monkeypatch.setattr(store, "get_dossiers", _get_dossiers)
    await host_dossier_prompt_block(
        {"192.168.10.202": "source", "": "destination"},
        ctx=_ctx(),
    )
    assert seen == ["192.168.10.202"]


# ---------------------------------------------------------------------------
# Which addresses does a piece of free text put in play?
# ---------------------------------------------------------------------------
#
# The investigation pipeline gets its host set from the alert's typed fields.
# The hunt console and the chats do not: they have an analyst's sentence, a
# stored objective, a conversation. `internal_ips_in_text` is the one answer to
# "which addresses here could the dossier speak about", so those three surfaces
# cannot drift into three different definitions of "ours".


def test_internal_ips_in_text_finds_them_in_order_and_dedups(settings_kratos: Settings) -> None:
    found = internal_ips_in_text(
        "did 192.168.10.202 probe 192.168.10.30, and what else did 192.168.10.202 touch?",
        settings_kratos,
    )
    assert found == ["192.168.10.202", "192.168.10.30"]


def test_internal_ips_in_text_leaves_public_addresses_out(settings_kratos: Settings) -> None:
    """An external address has no dossier and never will; naming it would spend
    the block's budget on a line that only ever says "no record"."""
    assert internal_ips_in_text("traffic to 8.8.8.8 and 203.0.113.7", settings_kratos) == []


def test_internal_ips_in_text_reads_ports_and_sentence_punctuation(
    settings_kratos: Settings,
) -> None:
    """The address is what the store is keyed on, so the port comes off — but
    the analyst's own spelling of the address is preserved (the egress guard
    allocates one label per spelling)."""
    assert internal_ips_in_text("sessions to 192.168.10.202:22.", settings_kratos) == [
        "192.168.10.202"
    ]


def test_internal_ips_in_text_reads_oqls_own_field_value_syntax(
    settings_kratos: Settings,
) -> None:
    """`field:value` is the query language this product TEACHES the model to
    write, and both callers of this function take analyst free text. An
    extractor that cannot read `source.ip:10.1.2.3` silently reproduces the
    exact failure the dossier exists to fix — the host is in the text and the
    model is never told what it is.
    """
    assert internal_ips_in_text("source.ip:192.168.10.202", settings_kratos) == ["192.168.10.202"]
    # …and the first address is not eaten by the colon while the second survives.
    assert internal_ips_in_text("ip:192.168.10.202 and dest 192.168.10.30", settings_kratos) == [
        "192.168.10.202",
        "192.168.10.30",
    ]


def test_internal_ips_in_text_reads_a_url(settings_kratos: Settings) -> None:
    """A path is not a CIDR prefix. An analyst pasting the management URL of the
    box they are asking about is naming that box."""
    assert internal_ips_in_text("http://192.168.10.202/admin was hit", settings_kratos) == [
        "192.168.10.202"
    ]
    assert internal_ips_in_text("https://192.168.10.202:8443/ui", settings_kratos) == [
        "192.168.10.202"
    ]


def test_internal_ips_in_text_ignores_a_cidr(settings_kratos: Settings) -> None:
    """ "Sweep 192.168.10.0/24" names a range, not a host. Describing its network
    address as a machine is a "no dossier" line about something that is not one."""
    assert internal_ips_in_text("sweep 192.168.10.0/24 for SSH", settings_kratos) == []


def test_internal_ips_in_text_is_not_ipv4_only(settings_kratos: Settings) -> None:
    """The dossier is keyed on whatever address the census observed, and the
    operator's own `internal_cidrs` decide which of those are ours."""
    settings = settings_kratos.model_copy(
        update={"internal_cidrs": [ip_network("fd00::/8"), ip_network("192.168.0.0/16")]}
    )
    assert internal_ips_in_text("fd00::1 answered", settings) == ["fd00::1"]


def test_internal_ips_in_text_reads_every_ipv6_spelling(settings_kratos: Settings) -> None:
    """Compressed, bracketed-with-port, OQL `field:value`, and the fully
    uncompressed form followed by a sentence period — the last is the spelling
    this codebase's own tool-surface tests use, and a trailing `.` must not eat
    it."""
    settings = settings_kratos.model_copy(
        update={"internal_cidrs": [ip_network("fd00::/8"), ip_network("192.168.0.0/16")]}
    )
    assert internal_ips_in_text("host fd00:0:0:0:0:0:0:1.", settings) == ["fd00:0:0:0:0:0:0:1"]
    assert internal_ips_in_text("[fd00::1]:8443/ui", settings) == ["fd00::1"]
    assert internal_ips_in_text("source.ip:fd00::1", settings) == ["fd00::1"]


def test_internal_ips_in_text_finds_nothing_in_ordinary_prose(settings_kratos: Settings) -> None:
    """Hex-shaped words, dates and versions are not addresses. Nothing here is
    an IP, so nothing is claimed to be a host."""
    assert (
        internal_ips_in_text(
            "on 2026-08-08 the deadbeef service at 00:11:22:33:44:55 ran v1.2.3",
            settings_kratos,
        )
        == []
    )


# ---------------------------------------------------------------------------
# known_only: the free-text surfaces must not manufacture their own grounding
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_known_only_drops_hosts_the_sweep_has_no_record_of(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A "no dossier" line is TEXT, and the grounding gate grounds by presence in
    the corpus — never by verifying the claim. On a surface whose addresses came
    from free text (an analyst's sentence, or the model's own previous turn),
    rendering that line for an address with no record makes the address ground
    ITSELF. ``known_only`` is what keeps those surfaces to hosts the network
    sweep actually knows.
    """
    from soc_ai.store import host_dossier as store

    monkeypatch.setattr(store, "get_dossiers", _stored_batch("192.168.10.202"))
    ips = {"192.168.10.202": "named in this conversation", "192.168.10.50": "named"}

    kept = await host_dossier_prompt_block(ips, ctx=_ctx(), known_only=True)

    assert "192.168.10.202" in kept
    assert "192.168.10.50" not in kept
    # No per-host absence LINE (the intro's own prose explains what a missing
    # record means and stays; it names no address, so it grounds nothing).
    assert not [chunk for chunk in _host_chunks(kept) if "no dossier:" in chunk]


@pytest.mark.asyncio
async def test_the_alert_path_still_states_a_missing_record_out_loud(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The default stays as it was. On the ALERT path the absence is
    load-bearing: the alert's own destination is a host under discussion, and
    "the sweep has no record of this address" is something the block owes the
    model about it — silence there reads as "nothing notable about that one"."""
    from soc_ai.store import host_dossier as store

    monkeypatch.setattr(store, "get_dossiers", _stored_batch("192.168.10.202"))
    ips = {"192.168.10.202": "source", "8.8.8.8": "destination"}

    block = await host_dossier_prompt_block(ips, ctx=_ctx())

    assert "8.8.8.8" in block
    assert "no dossier" in block


@pytest.mark.asyncio
async def test_known_only_renders_nothing_when_no_named_host_is_known(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every address came from free text and none has a record → no block at
    all, rather than a heading over an empty list."""
    from soc_ai.store import host_dossier as store

    monkeypatch.setattr(store, "get_dossiers", _stored_batch())

    block = await host_dossier_prompt_block({"192.168.10.50": "named"}, ctx=_ctx(), known_only=True)
    assert block == ""


def test_suppression_beats_the_pre_dropped_remainder() -> None:
    """The one boundary where a remainder is NOT stated, pinned deliberately.

    Nothing was found, so there is no shortened list to mistake for a complete
    one — and a heading over a lone "(+3 more hosts omitted)" would describe no
    host at all, which is exactly the noise the empty-output rule exists to
    prevent on a deployment that has not swept yet.
    """
    assert format_host_dossier_block([_absent("192.168.10.20")], omitted=3) == ""


def test_dossier_prompt_imports_without_the_agent_package() -> None:
    """``soc_ai.dossier.prompt`` must import on its own.

    ``soc_ai.dossier`` sits BELOW ``soc_ai.agent``, but the agent side imports
    this module at its own module scope, so an upward module-scope import here
    closes the loop: importing this module first raised ``ImportError`` on a
    partially-initialised module. It only ever worked because every real caller
    touched an agent module first — a load order nothing enforced, which broke a
    deploy-verification script. A subprocess is the only honest check; once any
    test in this session has imported the agent package the cycle is masked.
    """
    import subprocess
    import sys

    proc = subprocess.run(
        [sys.executable, "-c", "import soc_ai.dossier.prompt as p; print(p.MAX_PROMPT_HOSTS)"],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, f"importing dossier.prompt first failed:\n{proc.stderr}"
