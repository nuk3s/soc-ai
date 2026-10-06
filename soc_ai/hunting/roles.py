"""The role the dossier holds for each host, and the confidence behind it.

The prior sweep reads it to gate role priors. The estate refresh writes it on
every profile row, so ``profiles_for_role`` can read a peer group. Both read
the same map: an operator declaration at full confidence, else the inference
the sweep still believes.
"""

from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.store.models import HostDossier, HostDossierField

__all__ = ["CONFIDENT_ROLE", "name_keys", "role_for", "roles"]

# The confidence a role needs before a prior or a peer group reads it. A
# declared role counts as 1.0.
CONFIDENT_ROLE = 0.9


def name_keys(name: str) -> tuple[str, ...]:
    """The keys a hostname is looked up under: folded, and its short label.

    Sysmon and winlogbeat write ``host.name`` the way Windows says it, which is
    often upper-case and sometimes fully qualified, while the dossier holds
    whatever DHCP or NTLM handed it. ``WS01.corp.example`` and ``ws01`` are one
    machine and must find one role.
    """
    folded = name.strip().lower()
    if not folded:
        return ()
    label = folded.split(".", 1)[0]
    return (folded, label) if label != folded else (folded,)


def role_for(
    roles: dict[str, tuple[str | None, float]], entity_key: str
) -> tuple[str | None, float]:
    """The role held for an entity keyed either by IP or by ``host.name``."""
    if entity_key in roles:
        return roles[entity_key]
    for key in name_keys(entity_key):
        if key in roles:
            return roles[key]
    return (None, 0.0)


async def roles(db: AsyncSession) -> dict[str, tuple[str | None, float]]:
    """Every host's effective role and the confidence behind it.

    An operator declaration outranks the inference, and carries full
    confidence: a human who has declared a machine's role is not a 0.5 guess,
    and leaving it below the gate would make every declared host blind — the
    exact opposite of what declaring one is for.

    Keyed on the dossier's IP AND on the hostname the dossier believes. The
    process and logon dimensions key their entities on ``host.name``, and a
    map keyed on the IP alone answered "role unknown" for every one of them:
    five of the shipped role priors could never evaluate, and declaring the
    role in the console changed nothing.
    """
    rows = (
        await db.execute(
            select(HostDossier.host_key, HostDossierField.field, HostDossierField)
            .join(HostDossierField, HostDossierField.dossier_id == HostDossier.id)
            .where(HostDossierField.field.in_(("role", "hostname")))
        )
    ).all()

    out: dict[str, tuple[str | None, float]] = {}
    names: dict[str, str] = {}
    for host_key, field, row in rows:
        if field == "hostname":
            # The same precedence as the role: what the operator declared,
            # else what the sweep still believes.
            if row.operator_value:
                names[host_key] = str(row.operator_value)
            elif row.inferred_value and row.inferred_retracted_at is None:
                names[host_key] = str(row.inferred_value)
            continue
        # Attributes read directly, never through getattr with a default. The
        # first cut guessed the column was ``override_value`` (it is
        # ``operator_value``) and the default turned that typo into "no
        # operator has ever declared a role", silently, on every host.
        if row.operator_value:
            out[host_key] = (str(row.operator_value), 1.0)
            continue

        # A retracted inference is not a belief. The sweep retracts a fact when
        # the evidence for it stops arriving, and carrying it on here would let
        # a prior score against a role the dossier has already given up on.
        if row.inferred_retracted_at is not None:
            out[host_key] = (None, 0.0)
            continue

        out[host_key] = (
            str(row.inferred_value) if row.inferred_value else None,
            float(row.inferred_confidence) if row.inferred_confidence is not None else 0.0,
        )

    # Two dossiers can believe the same label (a DHCP re-lease leaves the old
    # row behind; two domains share a short name). The label then holds the
    # strongest belief, and never "no belief": a stale row that has given up
    # its role must not blind the live machine that still carries the name.
    for host_key, name in names.items():
        belief = out.get(host_key)
        if belief is None or belief[0] is None:
            continue
        for key in name_keys(name):
            held = out.get(key)
            if held is None or held[0] is None or held[1] < belief[1]:
                out[key] = belief
    return out
