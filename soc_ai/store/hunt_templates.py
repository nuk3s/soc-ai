"""Persistence + builtin seed for hunt templates (E3.2).

A :class:`~soc_ai.store.models.HuntTemplate` row is a curated, parameterized hunt
starter — a named objective (the evolution of the Hunt Console's six static
"canned pill" strings) plus the ``required_datasets`` it needs. The
``GET /hunt-templates`` route annotates each with ``available``/``missing_datasets``
against the LIVE grid inventory so a template that needs telemetry the grid lacks
renders FLAGGED, not hidden.

Small-table CRUD in the runbooks/schedules mould (create / get / list_all /
update / delete), plus :func:`seed_builtins` — an IDEMPOTENT upsert of the seven
builtin templates matching the current pills. Seeding runs on every startup
(after ``run_migrations``); idempotence is keyed by ``name`` so a restart never
duplicates a builtin, and the builtin's fields are refreshed to the code's values
(the code, not a stale row, is the source of truth for a builtin).
"""

from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.store.models import HuntTemplate

# The default hunt window a template seeds (24h) — a sane, shared default that a
# schedule/hunt can override. Matches the inventory discovery's default window.
DEFAULT_WINDOW_MINUTES = 1440


@dataclass(frozen=True)
class _Builtin:
    """One shipped template: the pill's name + full objective + the telemetry it needs.

    Each ``required_datasets`` element is ONE requirement. An element may name
    several planes separated by :data:`ALTERNATIVE_SEP`, any one of which
    satisfies it — ``"zeek.rdp|system.security"`` is "RDP sessions, from either
    the Zeek log or Windows logon type 10". The wire type stays ``list[str]``
    so nothing upstream changes shape; the store normalises the element and the
    availability check splits it.
    """

    name: str
    objective_template: str
    required_datasets: tuple[str, ...]


# The seven builtin templates. `objective_template` text is VERBATIM from the
# frontend PRESETS (frontend/src/screens/Hunts.tsx) so the picker is a superset of
# the old static pills — same objectives, now availability-annotated. Each names
# the `event.dataset` values it correlates over; a grid missing one flags the
# template rather than hiding it (honesty over hiding). Four objectives also name
# the analytics tools (t_beacon_profile / t_dns_entropy_scan / t_first_seen /
# t_dcerpc_histogram) the hunt agent should reach for — the objective text is the
# agent's prompt, so naming the tool there is how a template steers tool choice.
_BUILTINS: tuple[_Builtin, ...] = (
    _Builtin(
        name="Beaconing to rare IPs",
        objective_template=(
            "Hunt for internal hosts that beacon to rare external IP addresses in "
            "the last 24 h. Look for a regular cadence, a low data volume and novel "
            "destinations. Use t_beacon_profile to measure the cadence. Use "
            "t_first_seen to find the novel destinations. Reach a conclusion after "
            "both tools run."
        ),
        required_datasets=("zeek.conn|network_traffic.flow|endpoint.events.network",),
    ),
    _Builtin(
        name="Credential abuse / lockouts",
        objective_template=(
            "Hunt for credential-abuse signals on the domain controllers. Look for "
            "account lockouts, failed-authentication spikes and Kerberoasting."
        ),
        # Lockouts (4740) and failed auth (4625) are Windows events; Kerberos
        # ticket activity is visible from either the Zeek log or 4768/4769.
        required_datasets=("zeek.kerberos|system.security",),
    ),
    _Builtin(
        name="Lateral movement",
        objective_template=(
            "Hunt for lateral movement between internal hosts. Look for SMB and "
            "admin-share access, PsExec-style service creation, and RDP sessions."
        ),
        # RDP sessions are logon type 10 in system.security on any grid that
        # ships Windows security logs, whether or not Zeek parses RDP there.
        required_datasets=(
            "zeek.smb_files",
            "zeek.rdp|system.security",
            "zeek.kerberos|system.security",
        ),
    ),
    _Builtin(
        name="DNS / C2 exfiltration",
        objective_template=(
            "Hunt for DNS tunneling and C2 exfiltration. Look for high-entropy DNS, "
            "high-volume DNS, long TXT records and beacons over DNS. Use "
            "t_dns_entropy_scan to measure the qname entropy and the volume. Reach "
            "a conclusion after the tool runs."
        ),
        required_datasets=("zeek.dns|network_traffic.dns",),
    ),
    _Builtin(
        name="New external services",
        objective_template=(
            "Hunt for internal hosts that expose or reach a new external service "
            "this week. The host must never have used that service before. Use "
            "t_first_seen to compare the recent destinations against its trailing "
            "baseline. The behavioural profile on the host page holds the same peer "
            "set. A destination absent from that peer set is the signal."
        ),
        required_datasets=("zeek.conn|network_traffic.flow|endpoint.events.network",),
    ),
    _Builtin(
        name="Suspicious PowerShell / LOLBins",
        objective_template=(
            "Hunt for suspicious PowerShell and living-off-the-land binary use "
            "across the endpoints."
        ),
        # Elastic Defend has no bare `endpoint` data stream. Process execution,
        # which is what a PowerShell or LOLBin hunt reads, is
        # `endpoint.events.process`; loaded modules are
        # `endpoint.events.library`, and so on. The old value matched nothing,
        # so this template reported missing telemetry on every Elastic Defend
        # grid there has ever been.
        required_datasets=("endpoint.events.process",),
    ),
    _Builtin(
        name="DCE-RPC abuse / DC attacks",
        objective_template=(
            "Hunt for domain-controller attack patterns in DCE-RPC. Look for "
            "Zerologon-style NetrServerAuthenticate floods, DCSync through "
            "DRSGetNCChanges, and remote service creation. Run t_dcerpc_histogram "
            "first. Investigate every flagged or rare dangerous operation."
        ),
        required_datasets=("zeek.dce_rpc",),
    ),
)


# ── Environment fit (the SECOND annotation axis) ─────────────────────────────
#
# `required_datasets` says whether the GRID can see the telemetry; these say
# whether the NETWORK has the machinery the hunt is about. A grid can carry
# zeek.kerberos while the network has two intermittent workgroup laptops and no
# domain — dataset presence ≠ relevance. Requirements live in CODE, not the DB
# (no migration, no operator bookkeeping): keyed by builtin NAME, the same key
# `seed_builtins` upserts on. Only builtins appear here — a custom operator
# template is ALWAYS applicable (the operator knows their network) — and
# absence means "network-generic". Consumers must DEMOTE, never hide: an
# attacker's first domain join must not be invisible because the catalogue
# decided this network "doesn't do domains".
ENV_WINDOWS = "windows"
ENV_DOMAIN = "domain"

BUILTIN_ENV_REQUIREMENTS: dict[str, tuple[str, ...]] = {
    "Credential abuse / lockouts": (ENV_DOMAIN,),
    "Lateral movement": (ENV_WINDOWS,),
    "Suspicious PowerShell / LOLBins": (ENV_WINDOWS,),
    # The four network-generic builtins (Beaconing, DNS/C2, New external
    # services, DCE-RPC abuse) are deliberately absent: every network qualifies.
    # DCE-RPC in particular is a DATASET gap (zeek.dce_rpc, flagged via
    # `available`/`missingDatasets` above), not an environment gap — DC attack
    # patterns don't presuppose a resolved domain-joined host the way
    # Kerberoasting or PsExec do, so it stays off this axis (flag-not-demote).
}

# requirement -> the human phrase the API reports in `missingEnvironment`.
ENV_REQUIREMENT_PHRASES: dict[str, str] = {
    ENV_DOMAIN: "a domain-joined host",
    ENV_WINDOWS: "a Windows host",
}


# One requirement, several planes that satisfy it. A hunt that three planes
# could serve used to be able to name only one, and reported itself
# unavailable everywhere else: on the range, "Lateral movement" required
# zeek.rdp, which that grid has never produced, while every RDP session sat
# in system.security as logon type 10.
ALTERNATIVE_SEP = "|"


def alternatives(requirement: str) -> tuple[str, ...]:
    """The planes that satisfy one ``required_datasets`` element, in order.

    Whitespace around each is dropped and empties are skipped, so a hand-typed
    ``" zeek.rdp | system.security "`` is the same requirement as the canonical
    form. A plain name is a one-element tuple.
    """
    return tuple(p.strip() for p in requirement.split(ALTERNATIVE_SEP) if p.strip())


def _norm_datasets(values: object) -> list[str]:
    """Coerce ``required_datasets`` into clean, de-duplicated requirements.

    Each element is re-joined from its :func:`alternatives`, so ``"a|"`` and
    ``"a"`` store as the same requirement and compare equal on the wire, and an
    element with no surviving plane is dropped. Anything non-list-like is ``[]``.
    """
    if not values or not isinstance(values, (list, tuple, set)):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for v in values:
        alts = alternatives(str(v))
        if not alts:
            continue
        s = ALTERNATIVE_SEP.join(dict.fromkeys(alts))
        if s not in seen:
            seen.add(s)
            out.append(s)
    return out


# The most analytics one starter may name. A starter that runs 30 analytics
# before it reads anything has spent the hunt's tool budget on the prologue.
MAX_TEMPLATE_ANALYTICS = 8


def _norm_analytics(values: object) -> list[str]:
    """Coerce ``analytics`` into a clean, de-duplicated, bounded id list.

    Blanks are dropped and order is kept, because the order is the order the
    objective asks the agent to run them in. Anything non-list-like is ``[]``.
    """
    if not values or not isinstance(values, (list, tuple, set)):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for v in values:
        s = str(v).strip()
        if not s or s in seen:
            continue
        seen.add(s)
        out.append(s[:64])
        if len(out) >= MAX_TEMPLATE_ANALYTICS:
            break
    return out


# ── CRUD ─────────────────────────────────────────────────────────────────────


async def create(
    db: AsyncSession,
    *,
    name: str,
    objective_template: str = "",
    required_datasets: list[str] | None = None,
    analytics: list[str] | None = None,
    default_window_minutes: int = DEFAULT_WINDOW_MINUTES,
    builtin: bool = False,
    created_by: str = "anonymous",
) -> HuntTemplate:
    """Create a template. ``required_datasets`` is normalized to a clean str list."""
    template = HuntTemplate(
        name=name[:256],
        objective_template=objective_template,
        required_datasets=_norm_datasets(required_datasets),
        analytics_json=_norm_analytics(analytics),
        default_window_minutes=max(int(default_window_minutes), 1),
        builtin=builtin,
        created_by=created_by[:128],
    )
    db.add(template)
    await db.commit()
    await db.refresh(template)
    return template


async def get(db: AsyncSession, template_id: int) -> HuntTemplate | None:
    return await db.get(HuntTemplate, template_id)


async def get_by_name(db: AsyncSession, name: str) -> HuntTemplate | None:
    rows = await db.scalars(select(HuntTemplate).where(HuntTemplate.name == name).limit(1))
    return rows.first()


async def list_all(db: AsyncSession, *, limit: int = 500) -> list[HuntTemplate]:
    """All templates, builtins first, then most-recently-created — a stable order
    for the picker (the shipped hunts lead, custom ones follow)."""
    rows = await db.scalars(
        select(HuntTemplate)
        .order_by(
            HuntTemplate.builtin.desc(),
            HuntTemplate.created_at.desc(),
            HuntTemplate.id.desc(),
        )
        .limit(limit)
    )
    return list(rows.all())


async def update(
    db: AsyncSession,
    template_id: int,
    *,
    name: str | None = None,
    objective_template: str | None = None,
    required_datasets: list[str] | None = None,
    analytics: list[str] | None = None,
    default_window_minutes: int | None = None,
) -> HuntTemplate | None:
    """Patch the given fields (``None`` = leave unchanged). Returns the row or None.

    ``builtin`` is never patchable through this path — a template's kind is fixed
    at creation (builtins come from :func:`seed_builtins`, customs from the route).
    """
    template = await db.get(HuntTemplate, template_id)
    if template is None:
        return None
    if name is not None:
        template.name = name[:256]
    if objective_template is not None:
        template.objective_template = objective_template
    if required_datasets is not None:
        template.required_datasets = _norm_datasets(required_datasets)
    if analytics is not None:
        template.analytics_json = _norm_analytics(analytics)
    if default_window_minutes is not None:
        template.default_window_minutes = max(int(default_window_minutes), 1)
    await db.commit()
    await db.refresh(template)
    return template


async def delete(db: AsyncSession, template_id: int) -> bool:
    """Hard-delete a template. Returns True if it existed.

    Callers gate on ``builtin`` BEFORE calling this — the route refuses to delete a
    builtin (409). This store helper deletes any row it's handed.
    """
    template = await db.get(HuntTemplate, template_id)
    if template is None:
        return False
    await db.delete(template)
    await db.commit()
    return True


# ── Builtin seed (idempotent, runs every startup) ─────────────────────────────


async def seed_builtins(db: AsyncSession) -> int:
    """Idempotently upsert the shipped builtin templates. Returns the count seeded/updated.

    Keyed by ``name``: a builtin that doesn't exist is inserted; one that already
    exists is refreshed to the code's current objective/datasets (the CODE, not a
    stale DB row, is the source of truth for a builtin's content). Safe to call on
    every startup — it never duplicates a builtin and never touches a custom
    (``builtin=False``) template.
    """
    n = 0
    for b in _BUILTINS:
        existing = await get_by_name(db, b.name)
        if existing is None:
            db.add(
                HuntTemplate(
                    name=b.name,
                    objective_template=b.objective_template,
                    required_datasets=list(b.required_datasets),
                    default_window_minutes=DEFAULT_WINDOW_MINUTES,
                    builtin=True,
                    created_by="system",
                )
            )
            n += 1
        elif existing.builtin:
            # Refresh a shipped builtin in place (a custom template that happens to
            # share a name is left untouched — the operator owns their rows).
            existing.objective_template = b.objective_template
            existing.required_datasets = list(b.required_datasets)
            n += 1
    await db.commit()
    return n
