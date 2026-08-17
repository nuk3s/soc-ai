"""The shipped ``EVENTS_INDEX_PATTERN`` must not be namespace-scoped.

On 2026-08-05 a production install ran ``EVENTS_INDEX_PATTERN=.ds-logs-*-so-*,
logs-synth-*``. That pattern names Elasticsearch *backing indices* directly and
so hard-codes the Elastic Agent namespace ``so`` — which silently excluded every
``-default-`` namespace data stream (``logs-system.auth-default`` ~117K docs,
``logs-system.syslog-default`` ~48M docs). The agent could not see logs that were
sitting right there and produced a wrong investigation. Nothing errored; the
pattern still matched 139M documents, so the doctor's "matched no documents"
warning never fired.

These tests pin the two invariants that stop it recurring:

1. the shipped default matches **data-stream names** (``logs-*``), which
   Elasticsearch expands to every backing index in every namespace; and
2. every operator-facing file that sets the variable agrees with that default
   *and* explains the namespace dimension, so the next person who narrows the
   pattern by hand knows what they are cutting out.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from soc_ai.config import Settings

REPO_ROOT = Path(__file__).resolve().parents[1]

#: Files an operator copies from or edits when wiring up a grid. Every one of
#: them ships a value for the events pattern, so every one of them is a place
#: the blind spot can be reintroduced.
_OPERATOR_FACING = (
    ".env.example",
    "setup.conf.example",
    "docs/DEPLOYMENT.md",
    "docs/SECURITY-ONION-SETUP.md",
)

#: `EVENTS_INDEX_PATTERN=<value>`, commented-out or live, in shell/env/markdown.
#: Stops at whitespace (so trailing `# comments` are dropped) and at the quoting
#: characters that wrap the value in markdown prose and shell snippets.
_ASSIGNMENT = re.compile(r"EVENTS_INDEX_PATTERN=([^\s\"'`}$]+)")

#: The cross-cluster form for a multi-node grid. Same data-stream semantics,
#: just addressed through remote-cluster search.
_CROSS_CLUSTER_PREFIX = "*:"


def _shipped_default() -> str:
    """The class default, independent of any ``.env`` on the dev box."""
    default = Settings.model_fields["events_index_pattern"].default
    assert isinstance(default, str)
    return default


def test_shipped_default_is_not_namespace_scoped() -> None:
    """The default must match data-stream names, not ``.ds-`` backing indices.

    A data stream's documents live in backing indices named
    ``.ds-<stream>-<date>-<generation>``; a pattern written against those names
    has to spell out the namespace segment, and any namespace left out of the
    list becomes invisible with no error.
    """
    default = _shipped_default()
    assert ".ds-" not in default, (
        f"default {default!r} addresses backing indices directly; that form has to "
        "enumerate Elastic Agent namespaces and silently drops the ones it misses"
    )
    assert default == "logs-*"


def test_shipped_default_covers_the_default_namespace() -> None:
    """If the default ever does enumerate namespaces, ``default`` must be in it.

    ``-default-`` is where Elastic's stock integrations land — system.auth and
    system.syslog, i.e. the SSH/login evidence an investigation leans on. It is
    the namespace the 2026-08-05 incident lost.
    """
    default = _shipped_default()
    if "-so-" in default:
        assert "-default-" in default, (
            f"default {default!r} pins the Security Onion namespace but drops "
            "`-default-` (system.auth / system.syslog) — the 2026-08-05 blind spot"
        )


@pytest.mark.parametrize("relpath", _OPERATOR_FACING)
def test_operator_facing_values_match_the_shipped_default(relpath: str) -> None:
    """No shipped file may hand an operator a narrower pattern than the default."""
    text = (REPO_ROOT / relpath).read_text(encoding="utf-8")
    values = _ASSIGNMENT.findall(text)
    assert values, f"{relpath} no longer documents EVENTS_INDEX_PATTERN"
    default = _shipped_default()
    for value in values:
        bare = value.removeprefix(_CROSS_CLUSTER_PREFIX)
        assert bare == default, (
            f"{relpath} ships EVENTS_INDEX_PATTERN={value!r}, which disagrees with "
            f"the code default {default!r}"
        )


def test_setup_sh_writes_the_shipped_default() -> None:
    """The guided installer is the main way ``.env`` gets its value.

    ``setup.sh`` probes the grid and writes a concrete pattern, so a default that
    drifts from the installer's fallback means the repo disagrees with itself —
    which is how the two competing patterns ended up in circulation.
    """
    text = (REPO_ROOT / "setup.sh").read_text(encoding="utf-8")
    default = _shipped_default()
    assert f"${{EVENTS_INDEX_PATTERN:-{default}}}" in text, (
        f"setup.sh's interactive fallback no longer offers {default!r}"
    )
    assert f"printf '{default}'" in text, (
        f"detect_events_pattern's fallback no longer returns {default!r}"
    )
    assert ".ds-" not in text, (
        "setup.sh writes a backing-index pattern, which pins Elastic Agent "
        "namespaces into every new install"
    )


@pytest.mark.parametrize("relpath", _OPERATOR_FACING)
def test_operator_facing_docs_explain_the_namespace_trap(relpath: str) -> None:
    """Each shipped file warns against narrowing to a single namespace.

    The default being right is not enough: the incident happened because someone
    narrowed a *correct* default by hand. The warning has to travel with the
    setting.
    """
    text = (REPO_ROOT / relpath).read_text(encoding="utf-8")
    assert "namespace" in text.lower(), f"{relpath} never mentions the namespace dimension"
    assert "-default-" in text, (
        f"{relpath} does not name the `-default-` namespace (system.auth / system.syslog)"
    )
    assert ".ds-" in text, f"{relpath} does not warn about `.ds-` backing-index patterns"
