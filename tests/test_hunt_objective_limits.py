"""Hunt objective length contract (dogfood 2026-08-06).

A long, carefully-written hunt brief — the kind an analyst actually wants to
give — was rejected with a bare 422. The cap was 2000 characters, which is
roughly a paragraph: far too tight for a real objective, and the failure gave
the analyst nothing to act on.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from soc_ai.api.webui.routes_hunts import MAX_OBJECTIVE_CHARS, HuntChatIn


def test_long_realistic_objective_is_accepted() -> None:
    """A detailed multi-paragraph brief must not 422."""
    objective = (
        "Hunt for credential-abuse and lateral movement across the network. "
        "Focus on: account lockouts, failed-auth spikes, Kerberoasting on the "
        "domain controllers, SMB admin-share access, PsExec-style service "
        "creation, and RDP between internal hosts. " * 20
    )
    assert len(objective) > 2000  # the old cap
    assert HuntChatIn(objective=objective).objective == objective


def test_cap_is_generous_but_bounded() -> None:
    """Bounded so a runaway paste can't blow the agent's context budget."""
    assert 4000 <= MAX_OBJECTIVE_CHARS <= 20000


def test_over_cap_still_rejected() -> None:
    with pytest.raises(ValidationError):
        HuntChatIn(objective="x" * (MAX_OBJECTIVE_CHARS + 1))


def test_blank_objective_still_rejected() -> None:
    """Unchanged: an empty objective burns a model call for nothing."""
    with pytest.raises(ValidationError):
        HuntChatIn(objective="")


def test_schedule_and_template_share_the_cap() -> None:
    """The same text lands in all three surfaces — one limit, one constant."""
    import inspect

    from soc_ai.api.webui import routes_hunts

    src = inspect.getsource(routes_hunts)
    # No stray hard-coded 2000s left behind on objective fields.
    assert "max_length=2000" not in src
    assert src.count("max_length=MAX_OBJECTIVE_CHARS") >= 4
