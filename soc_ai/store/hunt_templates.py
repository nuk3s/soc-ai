"""Persistence + builtin seed for hunt templates (E3.2).

A :class:`~soc_ai.store.models.HuntTemplate` row is a curated, parameterized hunt
starter — a named objective (the evolution of the Hunt Console's six static
"canned pill" strings) plus the ``required_datasets`` it needs. The
``GET /hunt-templates`` route annotates each with ``available``/``missing_datasets``
against the LIVE grid inventory so a template that needs telemetry the grid lacks
renders FLAGGED, not hidden.

Small-table CRUD in the runbooks/schedules mould (create / get / list_all /
update / delete), plus :func:`seed_builtins` — an IDEMPOTENT upsert of the six
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
    """One shipped template: the pill's name + full objective + the telemetry it needs."""

    name: str
    objective_template: str
    required_datasets: tuple[str, ...]


# The six builtin templates. `objective_template` text is VERBATIM from the
# frontend PRESETS (frontend/src/screens/Hunts.tsx) so the picker is a superset of
# the old static pills — same objectives, now availability-annotated. Each names
# the `event.dataset` values it correlates over; a grid missing one flags the
# template rather than hiding it (honesty over hiding).
_BUILTINS: tuple[_Builtin, ...] = (
    _Builtin(
        name="Beaconing to rare IPs",
        objective_template=(
            "Hunt for internal hosts beaconing to rare external IPs in the last 24h — "
            "regular cadence, low data volume, novel destinations."
        ),
        required_datasets=("zeek.conn",),
    ),
    _Builtin(
        name="Credential abuse / lockouts",
        objective_template=(
            "Hunt for credential-abuse signals: account lockouts, failed-auth spikes, "
            "and Kerberoasting on the domain controllers."
        ),
        required_datasets=("zeek.kerberos",),
    ),
    _Builtin(
        name="Lateral movement",
        objective_template=(
            "Hunt for lateral movement: SMB/admin-share access, PsExec-style service "
            "creation, and RDP between internal hosts."
        ),
        required_datasets=("zeek.smb_files", "zeek.rdp", "zeek.kerberos"),
    ),
    _Builtin(
        name="DNS / C2 exfiltration",
        objective_template=(
            "Hunt for DNS tunneling and C2 exfiltration: high-entropy or high-volume DNS, "
            "long TXT records, and beaconing over DNS."
        ),
        required_datasets=("zeek.dns",),
    ),
    _Builtin(
        name="New external services",
        objective_template=(
            "Hunt for internal hosts newly exposing or reaching new external services this "
            "week that they never used before."
        ),
        required_datasets=("zeek.conn",),
    ),
    _Builtin(
        name="Suspicious PowerShell / LOLBins",
        objective_template=(
            "Hunt for suspicious PowerShell and living-off-the-land binary use across endpoints."
        ),
        required_datasets=("endpoint",),
    ),
)


def _norm_datasets(values: object) -> list[str]:
    """Coerce ``required_datasets`` into a clean list of non-empty, de-duplicated
    strings (order-preserving). Anything non-list-like becomes ``[]``."""
    if not values or not isinstance(values, (list, tuple, set)):
        return []
    out: list[str] = []
    seen: set[str] = set()
    for v in values:
        s = str(v).strip()
        if s and s not in seen:
            seen.add(s)
            out.append(s)
    return out


# ── CRUD ─────────────────────────────────────────────────────────────────────


async def create(
    db: AsyncSession,
    *,
    name: str,
    objective_template: str = "",
    required_datasets: list[str] | None = None,
    default_window_minutes: int = DEFAULT_WINDOW_MINUTES,
    builtin: bool = False,
    created_by: str = "anonymous",
) -> HuntTemplate:
    """Create a template. ``required_datasets`` is normalized to a clean str list."""
    template = HuntTemplate(
        name=name[:256],
        objective_template=objective_template,
        required_datasets=_norm_datasets(required_datasets),
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
