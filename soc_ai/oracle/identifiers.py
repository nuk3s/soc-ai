"""Effective internal-identifier set: env-config overlaid with the managed list.

The Oracle egress sanitizer and the internal-IP classifier need a single merged
view of a deployment's internal identifiers. This module computes, per kind::

    effective(kind) = env_config(kind) + {active values} - {muted values}

where ``env_config`` is the operator's env/Settings value
(``oracle_internal_suffixes`` / ``oracle_extra_hosts`` / ``internal_cidrs``) and
the active/muted sets come from the ``internal_identifier`` table.

CONTRACT — what muting can and cannot suppress (security floor):
Muting suppresses only DB-managed (detected/manual) identifiers that are NOT
also part of the env/Settings config. The reserved special-use suffixes
(``.lan`` / ``.local`` / ``.internal`` / ``.corp``) and any operator-configured
``oracle_internal_suffixes`` / ``oracle_extra_hosts`` are ALWAYS redacted as a
defense-in-depth floor and cannot be muted away via the table.

This module subtracts a muted value from the merged set, but for a value that is
also an env/reserved default the egress sanitizer re-introduces it: the sanitizer
(:func:`soc_ai.oracle.sanitize._resolve_suffixes`) always prepends
``settings.oracle_internal_suffixes`` (falling back to the reserved
``_DEFAULT_SUFFIXES``) as a floor, so muting one of those defaults here has no
net effect — the suffix is still redacted (fail-safe). Reserved special-use
suffixes are never public, so always redacting them is the correct, desirable
security contract. The net effective set the sanitizer applies is therefore::

    effective(kind) =
        (env/reserved config, always)
      + (active detected/manual DB identifiers)
      - (muted DB identifiers that are not env/reserved defaults)

Return shapes line up with the existing consumers so this resolver can later
replace the raw settings reads without changing call sites:

* ``suffixes`` → ``tuple[str, ...]`` (matches ``oracle_internal_suffixes``)
* ``hosts``    → ``tuple[str, ...]`` (the sanitizer call ``tuple()``-wraps
  ``oracle_extra_hosts``)
* ``cidrs``    → ``list[IPv4Network | IPv6Network]`` (matches the element type
  ``Settings.network_is_internal`` iterates over ``internal_cidrs``)

This resolver IS wired into both consumers: the orchestrator resolves the
effective set once per investigation and threads ``.suffixes``/``.hosts`` into
the Oracle egress sanitizer and ``.cidrs`` into the internal-vs-external
classifier — covering both the solicited-ICMP downgrade path AND the Phase-A
per-IP enrichment ``internal`` flag, so an activated ``cidr`` row classifies
hosts consistently across one investigation.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from ipaddress import IPv4Network, IPv6Network
from typing import TYPE_CHECKING

from soc_ai.store.internal_identifiers import list_identifiers, normalize

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession

    from soc_ai.config import Settings

IpNetwork = IPv4Network | IPv6Network


@dataclass(frozen=True)
class EffectiveIdentifiers:
    """The merged internal-identifier set, ready for the sanitizer/classifier."""

    suffixes: tuple[str, ...]
    hosts: tuple[str, ...]
    cidrs: list[IpNetwork]


def _merge_strings(
    kind: str,
    env_values: list[str],
    active: list[str],
    muted: set[str],
) -> tuple[str, ...]:
    """Merge env-config + active - muted for a string-valued kind, deduped.

    Env values are normalized to the same canonical form as stored values so a
    muted row matches an env-config value here. NOTE: subtracting a value that is
    also an env/reserved default has no NET effect for suffixes — the egress
    sanitizer (:func:`soc_ai.oracle.sanitize._resolve_suffixes`) always re-adds
    ``settings.oracle_internal_suffixes`` (and the reserved ``_DEFAULT_SUFFIXES``
    floor), so a muted reserved/env default is still redacted (fail-safe). Muting
    only effectively suppresses DB-managed identifiers absent from the env config.
    Order is preserved: normalized env values first, then active stored values.
    """
    out: list[str] = []
    seen: set[str] = set()
    for raw in [*env_values, *active]:
        try:
            norm = normalize(kind, raw)
        except ValueError:
            continue
        if norm in muted or norm in seen:
            continue
        seen.add(norm)
        out.append(norm)
    return tuple(out)


async def effective_internal_identifiers(
    db: AsyncSession, settings: Settings
) -> EffectiveIdentifiers:
    """Compute the effective internal-identifier set per kind.

    For each kind, ``env_config union active minus muted`` with dedup. Muting
    effectively suppresses only DB-managed (detected/manual) identifiers that are
    NOT also env/reserved defaults: the egress sanitizer re-adds
    ``settings.oracle_internal_suffixes`` (plus the reserved ``_DEFAULT_SUFFIXES``
    floor) regardless, so a muted reserved/env-default suffix is still redacted
    (fail-safe). See the module docstring for the full contract.
    """
    # list_identifiers excludes dismissed tombstones by default, and the
    # active/muted branches below ignore any other state (defense-in-depth):
    # a dismissed row contributes NOTHING to the effective set — it neither
    # activates nor subtracts an env default the way a muted row does.
    rows = await list_identifiers(db)
    active: dict[str, list[str]] = {"suffix": [], "host": [], "cidr": []}
    muted: dict[str, set[str]] = {"suffix": set(), "host": set(), "cidr": set()}
    for row in rows:
        if row.kind not in active:
            continue
        if row.state == "active":
            active[row.kind].append(row.value)
        elif row.state == "muted":
            muted[row.kind].add(row.value)

    suffixes = _merge_strings(
        "suffix",
        list(settings.oracle_internal_suffixes),
        active["suffix"],
        muted["suffix"],
    )
    hosts = _merge_strings(
        "host",
        list(settings.oracle_extra_hosts),
        active["host"],
        muted["host"],
    )

    # CIDRs: normalize env strings + stored values to canonical network strings,
    # subtract muted, dedup, then parse to ipaddress networks for the consumer.
    env_cidrs = [str(net) for net in settings.internal_cidrs]
    cidr_strs = _merge_strings("cidr", env_cidrs, active["cidr"], muted["cidr"])
    cidrs: list[IpNetwork] = [ipaddress.ip_network(s, strict=False) for s in cidr_strs]

    return EffectiveIdentifiers(suffixes=suffixes, hosts=hosts, cidrs=cidrs)
