"""Canonicalise a user principal across the spellings the grid uses.

One person appears on this grid as ``RANGE\\alice`` in ``system.security``,
``alice@corp.example`` in Kerberos, and bare ``alice`` in an audit message. Until
those collapse to one key, a host-to-user binding cannot form and a per-user
profile counts one person as three.

The domain is DROPPED rather than kept. Keeping it is the obvious choice and
the wrong one: two planes on the same grid disagree about which form they emit,
so a domain-qualified key produces two entities for one person and the binding
never forms. The cost of dropping it — two people with the same account name in
different domains collide — is real but rarer, and it fails toward one entity
with a muddled profile rather than toward a binding that never exists.

Machine accounts keep their trailing ``$`` because it is what makes them
identifiable as machines, and their memberships constrain nothing.

Well-known local accounts are NOT global identities. ``SYSTEM`` on one host is
not ``SYSTEM`` on another, and collapsing them would bind every machine in the
estate to a single entity whose profile means nothing.
"""

from __future__ import annotations

import re
from enum import Enum

__all__ = [
    "PrincipalKind",
    "canonical_principal",
    "is_machine_account",
    "principal_kind",
]

_SID_RE = re.compile(r"\AS-\d-\d+(?:-\d+)*\Z", re.IGNORECASE)

# Rejected outright: these are how the planes spell "no principal here", and
# each one would otherwise become an entity with a profile of its own.
_PLACEHOLDERS = frozenset({"", "-", "--", "n/a", "na", "null", "none", "unknown", "?"})

# Local to the machine they appear on, never a global identity.
_LOCAL_ACCOUNTS = frozenset(
    {
        "system",
        "local service",
        "localservice",
        "network service",
        "networkservice",
        "anonymous logon",
        "anonymous",
        "iusr",
        "dwm-1",
        "dwm-2",
        "dwm-3",
        "umfd-0",
        "umfd-1",
        "umfd-2",
    }
)

_LOCAL_AUTHORITIES = frozenset({"nt authority", "nt service", "builtin", "font driver host"})


class PrincipalKind(Enum):
    """What sort of principal a spelling denotes."""

    USER = "user"
    MACHINE = "machine"
    SID = "sid"
    LOCAL = "local"


def _strip_domain(value: str) -> tuple[str, str | None]:
    """Split ``DOMAIN\\user`` or ``user@domain`` into (account, domain).

    ``rpartition`` on the UPN form so ``first.last@corp.example`` keeps its dot —
    splitting on the first separator instead loses half the account name.
    """
    if "\\" in value:
        domain, _, account = value.partition("\\")
        return account.strip(), domain.strip().lower() or None
    if "@" in value:
        account, _, domain = value.rpartition("@")
        return account.strip(), domain.strip().lower() or None
    return value, None


def canonical_principal(value: str | None) -> str | None:
    """The one key every spelling of this principal collapses to.

    Returns None for anything that is not a principal, so a caller can tell
    "no principal on this document" from "a principal named none".
    """
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    if not stripped or stripped.lower() in _PLACEHOLDERS:
        return None

    if _SID_RE.match(stripped):
        # Already canonical and case-insensitive. Uppercased to match the way
        # Windows renders it, so the two sit side by side legibly.
        return stripped.upper()

    account, _domain = _strip_domain(stripped)
    if not account or account.lower() in _PLACEHOLDERS:
        return None
    return account.lower()


def is_machine_account(value: str | None) -> bool:
    """A machine account — trailing ``$`` — whose memberships constrain nothing."""
    canonical = canonical_principal(value)
    return canonical is not None and canonical.endswith("$")


def principal_kind(value: str | None) -> PrincipalKind | None:
    """Classify a spelling, or None if it does not denote a principal.

    Machine accounts are checked before the local-account table: a domain
    controller's own ``SR-DC01$`` is a global identity that several priors
    read, and folding it in with ``SYSTEM`` would lose it.
    """
    if not isinstance(value, str):
        return None
    stripped = value.strip()
    if not stripped or stripped.lower() in _PLACEHOLDERS:
        return None
    if _SID_RE.match(stripped):
        return PrincipalKind.SID

    account, domain = _strip_domain(stripped)
    lowered = account.lower()
    if not lowered:
        return None
    if lowered.endswith("$"):
        return PrincipalKind.MACHINE
    if domain in _LOCAL_AUTHORITIES or lowered in _LOCAL_ACCOUNTS:
        return PrincipalKind.LOCAL
    return PrincipalKind.USER
