"""Docs-vs-code accuracy gate (review Tier-0 rec #2).

The 2026-07-03 full review found user-facing doc claims that had silently gone
stale. This module is a lightweight regression gate that fails when the two
highest-drift surfaces diverge from the code:

1. ``docs/AGENT_TOOLS.md`` "Read tools" table  ==  the read tools actually
   registered on the agents (orchestrator / hunt / chat ``t_*`` functions,
   plus the ``@tool`` registry).
2. Every audit-event kind emitted in code is a member of the ``AuditKind``
   Literal in ``soc_ai/audit/schemas.py`` — a kind that is emitted but not
   declared fails ``AuditEvent`` validation at runtime and is *silently
   dropped* from the audit trail (the exact ``auto_ack`` bug class this
   review found; see the comment above ``"auto_ack"`` in schemas.py).

Hermetic by design: parses the doc + source files with regex relative to the
repo root and imports only ``soc_ai`` modules already imported elsewhere in
the suite. No network, no app startup, no new dependencies.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import get_args

REPO_ROOT = Path(__file__).resolve().parents[1]
AGENT_TOOLS_DOC = REPO_ROOT / "docs" / "AGENT_TOOLS.md"

# The modules that register tools on a pydantic-ai agent as `t_*` functions.
# Since the toolset unification every read tool is defined once in
# soc_ai/agent/toolset.py; the three agent modules are kept in the scan so a
# future inline registration is still caught. A new agent module that
# registers tools must be added here (the sanity test below keeps the scan
# honest).
AGENT_TOOL_SOURCES = (
    REPO_ROOT / "soc_ai" / "agent" / "toolset.py",
    REPO_ROOT / "soc_ai" / "agent" / "orchestrator.py",
    REPO_ROOT / "soc_ai" / "agent" / "hunt.py",
    REPO_ROOT / "soc_ai" / "agent" / "chat_agent.py",
)

# ---------------------------------------------------------------------------
# Gate 1 — AGENT_TOOLS.md read-tools table == registered read-tool surface
# ---------------------------------------------------------------------------

# Doc display name -> registered function name. `query_events` is the
# analyst-facing/MCP name (soc_ai/mcp_server/server.py registers the MCP tool
# as `query_events`); the agent-registered function is `query_events_oql`
# (soc_ai/tools/query_events.py, exposed to agents as `t_query_events_oql`).
DOC_NAME_ALIASES: dict[str, str] = {"query_events": "query_events_oql"}

# Registered in the @tool registry but deliberately NOT in the read-tools
# table: the doc's "Not a callable tool" note explains that get_alert_context
# runs deterministically in prefetch and is never handed to the agent. The
# test below asserts the note is still present so this skip stays honest.
REGISTERED_BUT_NOT_AGENT_CALLABLE = {"get_alert_context"}


def _read_tools_section() -> str:
    text = AGENT_TOOLS_DOC.read_text(encoding="utf-8")
    assert "## Read tools" in text, f"'## Read tools' heading missing from {AGENT_TOOLS_DOC}"
    section = text.split("## Read tools", 1)[1]
    # Section ends at the next H2 heading.
    return re.split(r"\n## ", section, maxsplit=1)[0]


def _documented_read_tools() -> set[str]:
    """Tool names from the first column of the read-tools markdown table.

    Cells look like ``` `query_events` ``` or ``` `get_pcap` / `t_get_pcap` ```;
    every backtick span that looks like an identifier counts. Names are
    normalized: the ``t_`` agent-registration prefix is stripped and the
    doc-name aliases applied, so both spellings map to the registered name.
    """
    names: set[str] = set()
    for line in _read_tools_section().splitlines():
        if not line.lstrip().startswith("|"):
            continue
        cells = line.split("|")
        if len(cells) < 2:
            continue
        first_cell = cells[1]
        if set(first_cell.strip()) <= {"-", ":", " "} or first_cell.strip() == "Tool":
            continue  # header / separator row
        for span in re.findall(r"`([^`]+)`", first_cell):
            if re.fullmatch(r"[a-z][a-z0-9_]*", span):
                names.add(span)
    normalized = {n.removeprefix("t_") for n in names}
    return {DOC_NAME_ALIASES.get(n, n) for n in normalized}


def _agent_registered_read_tools() -> set[str]:
    """The read tools the agents can actually call.

    Union of (a) every ``async def t_<name>`` registered on the triage/hunt/
    chat agents (source scan — hermetic, catches conditionally-registered
    tools like t_get_pcap/t_web_search) and (b) every read-only ``@tool`` in
    the registry (catches a tool that is registered but not yet wired to an
    agent), minus the documented not-agent-callable skip set.
    """
    t_names: set[str] = set()
    for src in AGENT_TOOL_SOURCES:
        t_names |= set(re.findall(r"async def (t_[a-z0-9_]+)\(", src.read_text(encoding="utf-8")))
    surface = {n.removeprefix("t_") for n in t_names}

    # Importing the agents force-registers every @tool module (same trick as
    # tests/test_agent_tools.py), then the registry lists the read-only ones.
    import soc_ai.agent.chat_agent
    import soc_ai.agent.orchestrator  # noqa: F401
    from soc_ai.tools._registry import list_tools

    registry_read = {s.name for s in list_tools(only_read_only=True)}
    surface |= registry_read - REGISTERED_BUT_NOT_AGENT_CALLABLE
    return surface


def test_read_tools_doc_table_parses() -> None:
    """Parsing sanity: a doc reformat must fail loudly, not as an empty set."""
    documented = _documented_read_tools()
    assert len(documented) >= 15, (
        f"only parsed {sorted(documented)} from the '## Read tools' table in "
        f"{AGENT_TOOLS_DOC} — did the table format change? Update the parser "
        "in tests/test_docs_accuracy.py."
    )


def test_agent_tool_scan_parses() -> None:
    """Parsing sanity for the code side of the comparison."""
    surface = _agent_registered_read_tools()
    assert len(surface) >= 15, (
        f"only found {sorted(surface)} registered read tools — did tool "
        "registration move out of soc_ai/agent/{orchestrator,hunt,chat_agent}.py "
        "or the @tool registry? Update AGENT_TOOL_SOURCES in this test."
    )


def test_every_registered_read_tool_is_documented() -> None:
    """A newly added agent read tool MUST be added to docs/AGENT_TOOLS.md."""
    undocumented = _agent_registered_read_tools() - _documented_read_tools()
    assert not undocumented, (
        f"read tools registered in code but MISSING from the '## Read tools' "
        f"table in {AGENT_TOOLS_DOC}: {sorted(undocumented)}. Add a row for "
        "each (or, if one is intentionally not agent-callable, add it to "
        "REGISTERED_BUT_NOT_AGENT_CALLABLE in tests/test_docs_accuracy.py "
        "AND to the doc's 'Not a callable tool' note)."
    )


def test_every_documented_read_tool_exists() -> None:
    """A documented tool that no longer exists in code is stale-doc drift."""
    ghosts = _documented_read_tools() - _agent_registered_read_tools()
    assert not ghosts, (
        f"tools documented in the '## Read tools' table of {AGENT_TOOLS_DOC} "
        f"but NOT registered anywhere in code: {sorted(ghosts)}. Remove the "
        "stale row(s) or fix the tool name (aliases: DOC_NAME_ALIASES in "
        "tests/test_docs_accuracy.py)."
    )


def test_not_callable_note_still_documents_skip_set() -> None:
    """Keep REGISTERED_BUT_NOT_AGENT_CALLABLE honest: each skipped name must
    still be explicitly called out in the doc's 'Not a callable tool' note."""
    section = _read_tools_section()
    assert "Not a callable tool" in section, (
        f"the 'Not a callable tool' note disappeared from {AGENT_TOOLS_DOC}; "
        "REGISTERED_BUT_NOT_AGENT_CALLABLE in tests/test_docs_accuracy.py "
        "relies on it — re-add the note or empty the skip set."
    )
    for name in REGISTERED_BUT_NOT_AGENT_CALLABLE:
        assert name in section, (
            f"{name!r} is skipped by REGISTERED_BUT_NOT_AGENT_CALLABLE but no "
            f"longer mentioned in the read-tools section of {AGENT_TOOLS_DOC}."
        )


# ---------------------------------------------------------------------------
# Gate 2 — every emitted audit-event kind is declared in AuditKind
# ---------------------------------------------------------------------------
#
# Emission scan scope (why these patterns / files):
#   * `_ev("<kind>"` and `emit_ev("<kind>"` in soc_ai/agent/orchestrator.py —
#     every such StepEvent is fed to `_audit()` -> `audit.log_kind()` ->
#     `AuditEvent(kind=...)`, where a kind outside AuditKind raises a
#     ValidationError that is caught and the event silently DROPPED from the
#     audit trail. soc_ai/api/hunt_runner.py also has an `_ev()` helper, but
#     its StepEvents (hunt_started/hunt_report/...) are SSE-only and never
#     written to the audit log, so it is deliberately out of scope — if hunts
#     ever start auditing, add the file here and the kinds to AuditKind.
#   * `.log_kind(<session>, "<kind>"` anywhere — direct audit writes
#     (e.g. soc_ai/tools/write_exec.py).
#   * `StepEvent(kind="<kind>"` anywhere — direct literal constructions.
#   * `record_event("<kind>"` anywhere — Prometheus metrics. Metric kinds are
#     plain counter labels (MetricsRecorder.record_event takes `kind: str`),
#     NOT audit events, so they may legitimately live outside AuditKind; they
#     get their own explicit allowlist so a NEW metric-only kind is a
#     conscious decision, not silent drift.

METRICS_ONLY_KINDS = {
    # Reliability counters emitted straight to Prometheus in orchestrator.py;
    # never written to the audit trail.
    "fallback_verdict",
    "zero_tool_verdict_blocked",
}

_AUDIT_EMISSION_PATTERNS = (
    # \w*_ev( matches both the `_ev(` helpers and `emit_ev(`; \s* spans the
    # newline in multi-line calls like `_ev(\n    "targeted_dispatch", ...`.
    (r'\w*_ev\(\s*"([a-z0-9_]+)"', (REPO_ROOT / "soc_ai" / "agent" / "orchestrator.py",)),
    (r'\.log_kind\(\s*[\w.\[\]]+,\s*"([a-z0-9_]+)"', None),  # None => all of soc_ai/
    (r'StepEvent\(\s*kind="([a-z0-9_]+)"', None),
)
_METRIC_EMISSION_PATTERN = r'record_event\(\s*"([a-z0-9_]+)"'


def _soc_ai_sources() -> list[Path]:
    return [p for p in (REPO_ROOT / "soc_ai").rglob("*.py") if "__pycache__" not in p.parts]


def _scan(pattern: str, files: list[Path] | tuple[Path, ...]) -> dict[str, list[str]]:
    """kind -> ['relative/path:line', ...] for every match of pattern."""
    found: dict[str, list[str]] = {}
    for path in files:
        text = path.read_text(encoding="utf-8")
        for m in re.finditer(pattern, text):
            line = text.count("\n", 0, m.start()) + 1
            found.setdefault(m.group(1), []).append(f"{path.relative_to(REPO_ROOT)}:{line}")
    return found


def _emitted_audit_kinds() -> dict[str, list[str]]:
    all_sources = _soc_ai_sources()
    emitted: dict[str, list[str]] = {}
    for pattern, files in _AUDIT_EMISSION_PATTERNS:
        for kind, locs in _scan(pattern, files if files is not None else all_sources).items():
            emitted.setdefault(kind, []).extend(locs)
    return emitted


def _declared_audit_kinds() -> set[str]:
    from soc_ai.audit.schemas import AuditKind

    return set(get_args(AuditKind))


def test_audit_kind_scan_parses() -> None:
    """Parsing sanity: the emission scan must keep finding real emissions."""
    emitted = _emitted_audit_kinds()
    assert len(emitted) >= 10, (
        f"audit-emission scan only found kinds {sorted(emitted)} — did the "
        "_ev/log_kind emission helpers get renamed? Update the patterns in "
        "tests/test_docs_accuracy.py."
    )
    assert "session_start" in emitted and "triage_report" in emitted


def test_every_emitted_audit_kind_is_declared() -> None:
    """THE hard gate: emitted ⊆ AuditKind.

    A kind emitted here but absent from the AuditKind Literal makes
    AuditEvent validation raise inside `_audit`/`log_kind`; the exception is
    swallowed and the event never reaches the audit trail — the auto_ack bug
    class. Fix = add the kind to AuditKind in soc_ai/audit/schemas.py.
    """
    declared = _declared_audit_kinds()
    undeclared = {
        kind: locs for kind, locs in _emitted_audit_kinds().items() if kind not in declared
    }
    assert not undeclared, (
        "audit-event kinds emitted in code but MISSING from the AuditKind "
        "Literal in soc_ai/audit/schemas.py (these events fail AuditEvent "
        "validation and are silently dropped from the audit trail):\n"
        + "\n".join(
            f"  {kind!r} emitted at {', '.join(locs)}" for kind, locs in sorted(undeclared.items())
        )
    )


def test_metric_only_kinds_are_allowlisted() -> None:
    """A new `record_event("<kind>")` must be either a declared AuditKind or a
    consciously allowlisted metrics-only counter."""
    declared = _declared_audit_kinds() | METRICS_ONLY_KINDS
    unknown = {
        kind: locs
        for kind, locs in _scan(_METRIC_EMISSION_PATTERN, _soc_ai_sources()).items()
        if kind not in declared
    }
    assert not unknown, (
        "metric kinds emitted via record_event() that are neither AuditKind "
        "members nor in METRICS_ONLY_KINDS (tests/test_docs_accuracy.py):\n"
        + "\n".join(f"  {kind!r} at {', '.join(locs)}" for kind, locs in sorted(unknown.items()))
    )


# Reverse check (nice-to-have, deliberately lenient): every declared kind
# should still be *referenced* somewhere in soc_ai/ source. Kinds produced
# only via dynamic values today (no string literal outside schemas.py) are
# allowlisted rather than deleted — revisit when touching the audit schema.
DECLARED_KINDS_WITHOUT_LITERAL_EMISSION = {
    "llm_request",
    "llm_response",
    "approval_decision",
    "session_end",
}


def test_every_declared_audit_kind_is_referenced_somewhere() -> None:
    schemas = REPO_ROOT / "soc_ai" / "audit" / "schemas.py"
    sources = [p for p in _soc_ai_sources() if p != schemas]
    corpus = "\n".join(p.read_text(encoding="utf-8") for p in sources)
    unreferenced = {
        kind
        for kind in _declared_audit_kinds() - DECLARED_KINDS_WITHOUT_LITERAL_EMISSION
        if f'"{kind}"' not in corpus and f"'{kind}'" not in corpus
    }
    assert not unreferenced, (
        f"AuditKind members never referenced anywhere in soc_ai/ outside "
        f"schemas.py: {sorted(unreferenced)}. Either the kind is dead (remove "
        "it) or it is emitted dynamically (add it to "
        "DECLARED_KINDS_WITHOUT_LITERAL_EMISSION in tests/test_docs_accuracy.py)."
    )
