"""Docs-vs-code accuracy gate (review Tier-0 rec #2).

The 2026-07-03 full review found user-facing doc claims that had silently gone
stale. This module is a lightweight regression gate that fails when the
highest-drift surfaces diverge from the code:

1. ``docs/AGENT_TOOLS.md`` "Read tools" table  ==  the read tools actually
   registered on the agents (orchestrator / hunt / chat ``t_*`` functions,
   plus the ``@tool`` registry).
2. Every audit-event kind emitted in code is a member of the ``AuditKind``
   Literal in ``soc_ai/audit/schemas.py`` — a kind that is emitted but not
   declared fails ``AuditEvent`` validation at runtime and is *silently
   dropped* from the audit trail (the exact ``auto_ack`` bug class this
   review found; see the comment above ``"auto_ack"`` in schemas.py).
3. ``docs/AGENT_TOOLS.md`` "Proposal tools" table  ==  the ``propose_*`` tools
   registered on the chat agents. These are the third capability class, and
   the one a reader is most likely to mis-model: they are neither read tools
   (they change what the UI offers) nor write tools (they touch nothing
   upstream). A proposal tool that ships undocumented leaves the doc claiming
   a "complete capability surface" that omits the only way the agent can put a
   verdict or a hunt in front of an analyst.

Hermetic by design: parses the doc + source files with regex relative to the
repo root and imports only ``soc_ai`` modules already imported elsewhere in
the suite. No network, no app startup, no new dependencies.
"""

from __future__ import annotations

import re
import tomllib
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
# Gate 3 — AGENT_TOOLS.md "Proposal tools" table == registered propose_* tools
# ---------------------------------------------------------------------------
#
# Proposal tools are registered inline in soc_ai/agent/chat_agent.py rather
# than in the shared toolset, because each one closes over the sink its caller
# passes; they carry no `t_` prefix, so Gate 1's scan cannot see them at all.
# They are also opt-in per surface (no sink -> tool absent from the schema),
# which is exactly why the doc has to name them: whether the agent in front of
# you can propose a verdict, a hunt, or neither is a product fact, not an
# implementation detail.

PROPOSAL_TOOL_SOURCE = REPO_ROOT / "soc_ai" / "agent" / "chat_agent.py"
PROPOSAL_SECTION_HEADING = "## Proposal tools"


def _proposal_section() -> str:
    text = AGENT_TOOLS_DOC.read_text(encoding="utf-8")
    assert PROPOSAL_SECTION_HEADING in text, (
        f"{PROPOSAL_SECTION_HEADING!r} heading missing from {AGENT_TOOLS_DOC} — "
        "the doc must carry a section for the propose_* tools registered in "
        f"{PROPOSAL_TOOL_SOURCE.name}."
    )
    section = text.split(PROPOSAL_SECTION_HEADING, 1)[1]
    return re.split(r"\n## ", section, maxsplit=1)[0]


def _documented_proposal_tools() -> set[str]:
    """Tool names from the first column of the proposal-tools markdown table."""
    names: set[str] = set()
    for line in _proposal_section().splitlines():
        if not line.lstrip().startswith("|"):
            continue
        cells = line.split("|")
        if len(cells) < 2:
            continue
        first_cell = cells[1]
        if set(first_cell.strip()) <= {"-", ":", " "} or first_cell.strip() == "Tool":
            continue  # header / separator row
        names |= {
            span for span in re.findall(r"`([^`]+)`", first_cell) if span.startswith("propose_")
        }
    return names


def _registered_proposal_tools() -> set[str]:
    """Every ``propose_*`` tool the chat agent builder can register."""
    src = PROPOSAL_TOOL_SOURCE.read_text(encoding="utf-8")
    return set(re.findall(r"async def (propose_[a-z0-9_]+)\(", src))


def test_proposal_tool_scan_parses() -> None:
    """Parsing sanity: a rename or a move out of chat_agent.py must fail loudly
    here, not silently empty the comparison on both sides."""
    registered = _registered_proposal_tools()
    assert registered, (
        f"no `async def propose_*` found in {PROPOSAL_TOOL_SOURCE} — did proposal "
        "tools move to another module? Update PROPOSAL_TOOL_SOURCE in "
        "tests/test_docs_accuracy.py."
    )


def test_every_proposal_tool_is_documented() -> None:
    """A new propose_* tool MUST get a row in the doc's proposal-tools table."""
    undocumented = _registered_proposal_tools() - _documented_proposal_tools()
    assert not undocumented, (
        f"proposal tools registered in {PROPOSAL_TOOL_SOURCE.name} but MISSING "
        f"from the {PROPOSAL_SECTION_HEADING!r} table in {AGENT_TOOLS_DOC}: "
        f"{sorted(undocumented)}. Add a row saying which surface offers it and "
        "what the analyst has to confirm."
    )


def test_every_documented_proposal_tool_exists() -> None:
    """A documented proposal tool that no longer exists is stale-doc drift."""
    ghosts = _documented_proposal_tools() - _registered_proposal_tools()
    assert not ghosts, (
        f"proposal tools documented in {AGENT_TOOLS_DOC} but NOT registered in "
        f"{PROPOSAL_TOOL_SOURCE.name}: {sorted(ghosts)}. Remove the stale row(s)."
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


# ---------------------------------------------------------------------------
# Gate 4 — quickstart.md / README.md drift (onboarding-wedge review)
# ---------------------------------------------------------------------------
#
# docs/quickstart.md is now the one page that owns clone-to-verdict, and the
# README status badge is the first version number a visitor sees. Both rot
# silently: nobody edits a hand-written badge on every release, and a
# relative markdown link has no compiler to catch a typo'd target. The badge
# sat at 1.2.6 for two releases before this gate was added; that's the
# regression class these pin.

DOCS_DIR = REPO_ROOT / "docs"
QUICKSTART_DOC = DOCS_DIR / "quickstart.md"
README_DOC = REPO_ROOT / "README.md"


def test_readme_version_badge_matches_pyproject() -> None:
    """Pins the README status badge to pyproject's version — the badge sat at
    1.2.6 while the repo shipped 1.2.8; hand-edited badges rot."""
    version = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text())["project"]["version"]
    readme = README_DOC.read_text()
    m = re.search(r"badge/status-(\d+\.\d+\.\d+)-", readme)
    assert m is not None, "README status badge not found"
    assert m.group(1) == version, f"README badge {m.group(1)} != pyproject {version}"


def test_quickstart_internal_links_resolve() -> None:
    """Every relative .md link in the quickstart must exist — the page owns
    clone-to-verdict and a dangling link strands a first-run user."""
    text = QUICKSTART_DOC.read_text()
    for target in re.findall(r"\]\(([A-Za-z0-9_\-./]+\.md)(?:#[^)]*)?\)", text):
        assert (DOCS_DIR / target).exists() or (REPO_ROOT / target).exists(), (
            f"broken quickstart link: {target}"
        )


def test_quickstart_leads_with_the_demo() -> None:
    """Step 0 must stay the risk-free local demo (docker-compose.demo.yml was
    undocumented for months while fully working)."""
    text = QUICKSTART_DOC.read_text()
    first_section = re.split(r"(?m)^## ", text)[1]
    assert "docker-compose.demo.yml" in first_section


def test_quickstart_standing_one_up_anchor_matches_heading_slug() -> None:
    """Pins the anchor half of the quickstart's cross-doc link.

    quickstart.md links ``LESSER_MODELS.md#standing-one-up``. mkdocs' default
    toc-extension slugifier lowercases and hyphenates heading text, so
    ``## Standing one up`` -> ``standing-one-up`` (checked against a live
    ``markdown`` toc conversion while writing this test, not assumed blind;
    also confirmed by ``mkdocs build --strict`` + grepping the built site).
    The heading side of this pin — that docs/LESSER_MODELS.md still carries
    that exact ``## Standing one up`` heading — already lives in
    tests/test_setup_script.py::test_lesser_models_doc_has_standing_one_up_heading;
    this test only pins quickstart.md's href string so the two sides can't
    drift apart silently.
    """
    text = QUICKSTART_DOC.read_text()
    assert "LESSER_MODELS.md#standing-one-up" in text, (
        "quickstart.md no longer links LESSER_MODELS.md#standing-one-up — if "
        "the LESSER_MODELS.md heading text changed, update the anchor here to "
        "match its new slug (and re-verify with mkdocs build --strict)."
    )


# ---------------------------------------------------------------------------
# Gate 5 — the audit-grant ssh one-liner stays identical across its 4 homes
# (final-review batch, M5)
# ---------------------------------------------------------------------------
#
# An operator meets this command in four independent places depending on
# which doc/output led them there: the doctor's own FAIL hint, setup.sh's
# post-start warning, the quickstart's "one command" step, and the full SO
# prerequisites doc. A hand-edit to any one of them (a typo fix, a rewording)
# silently forks the recipe the other three still advertise. Extract the
# command from each file with the SAME pattern and compare the matches
# against each other, rather than hardcoding the golden string four times —
# a divergence fails on its own merits, not against a possibly-stale copy
# pinned here.
#
# The pattern is deliberately NOT fully literal: `\S+@\S+` and `\S*` let the
# placeholder (`<admin>@<so-manager>`) and the path ahead of the script name
# vary across matches, while the script name itself and the surrounding
# shell shape stay fixed. A fully literal pattern would make the distinct-
# set comparison below dead code: if every home has to match one exact fixed
# string to be found at all, the four extracted matches can never disagree
# with each other, so only the earlier "not found" assert could ever fire —
# the comparison would never be the thing that fails. With this looser
# shape, a home that rewords the placeholder or moves the script still
# MATCHES (the "not found" assert doesn't mask the drift) but extracts a
# genuinely different string, so the set comparison is what catches it.
_AUDIT_GRANT_SSH_PATTERN = re.compile(r"ssh \S+@\S+ 'sudo bash -s' < \S*setup-audit-index\.sh")
_AUDIT_GRANT_SSH_HOMES: dict[str, Path] = {
    "soc_ai/doctor.py": REPO_ROOT / "soc_ai" / "doctor.py",
    "setup.sh": REPO_ROOT / "setup.sh",
    "docs/quickstart.md": QUICKSTART_DOC,
    "docs/SECURITY-ONION-SETUP.md": DOCS_DIR / "SECURITY-ONION-SETUP.md",
}


def test_audit_grant_ssh_oneliner_identical_across_homes() -> None:
    """The audit-grant ssh one-liner must read byte-identical wherever an
    operator meets it — a fork here means someone followed a rewritten copy
    while the other three still point at whatever it drifted from."""
    found: dict[str, str] = {}
    for label, path in _AUDIT_GRANT_SSH_HOMES.items():
        m = _AUDIT_GRANT_SSH_PATTERN.search(path.read_text())
        assert m is not None, f"audit-grant ssh one-liner not found in {label}"
        found[label] = m.group(0)
    distinct = set(found.values())
    assert len(distinct) == 1, (
        f"the audit-grant ssh one-liner diverges across its homes: {found}. "
        "Make all four read byte-identical."
    )


# ---------------------------------------------------------------------------
# Gate 6 — advertised auto-triage caps == Settings defaults (final-review
# batch, M7)
# ---------------------------------------------------------------------------
#
# setup.sh's day-1 prompt and quickstart.md's install-step prose both quote
# the scheduler's caps (interval / per-sweep target cap / severity floor) as
# plain numbers so a first-run analyst knows what "on" means before opting
# in. Nothing re-derives those numbers from soc_ai.config.Settings, so a
# future default change (e.g. auto_triage_max_targets 25 -> 50) would leave
# both surfaces quietly advertising the old cap forever. Each assertion below
# derives its expected text FROM the live Settings default, so the direction
# of drift that matters — code changed, docs didn't — is what fails.
#
# Both files are read through _normalized_whitespace() before the substring
# check: quickstart.md's prose wraps at ~80 columns in the markdown source
# (rendering as one continuous sentence), so a cap phrase can straddle a
# source line break — e.g. "...capped at 25\ntargets a sweep..." — even
# though the rendered page reads it as one run of text. A raw substring check
# would false-fail on that wrap instead of on real drift.


def _normalized_whitespace(text: str) -> str:
    return " ".join(text.split())


def test_auto_triage_interval_matches_advertised_cap() -> None:
    """Pins the "every N min" cadence in setup.sh's prompt and quickstart's
    install-step prose to ``auto_triage_schedule_interval_minutes``."""
    from soc_ai.config import Settings

    minutes = Settings.model_fields["auto_triage_schedule_interval_minutes"].default
    needle = f"every {minutes} min"
    assert needle in _normalized_whitespace((REPO_ROOT / "setup.sh").read_text()), (
        f"setup.sh's auto-triage prompt no longer says {needle!r} — it must match "
        "Settings.auto_triage_schedule_interval_minutes."
    )
    assert needle in _normalized_whitespace(QUICKSTART_DOC.read_text()), (
        f"quickstart.md's install-step prose no longer says {needle!r} — it must "
        "match Settings.auto_triage_schedule_interval_minutes."
    )


def test_auto_triage_max_targets_matches_advertised_cap() -> None:
    """Pins the per-sweep target cap to ``auto_triage_max_targets`` — setup.sh
    and quickstart.md phrase the cap with different connector words
    ("targets/sweep" vs. "targets a sweep"), so each gets its own needle."""
    from soc_ai.config import Settings

    max_targets = Settings.model_fields["auto_triage_max_targets"].default
    assert f"≤{max_targets} targets/sweep" in _normalized_whitespace(
        (REPO_ROOT / "setup.sh").read_text()
    ), (
        f"setup.sh's auto-triage prompt no longer says '≤{max_targets} targets/sweep' "
        "— it must match Settings.auto_triage_max_targets."
    )
    assert f"{max_targets} targets a sweep" in _normalized_whitespace(QUICKSTART_DOC.read_text()), (
        f"quickstart.md's install-step prose no longer says "
        f"'{max_targets} targets a sweep' — it must match Settings.auto_triage_max_targets."
    )


def test_auto_triage_min_severity_matches_advertised_cap() -> None:
    """Pins the severity floor to ``auto_triage_min_severity``."""
    from soc_ai.config import Settings

    min_severity = Settings.model_fields["auto_triage_min_severity"].default
    needle = f"{min_severity}-severity"
    assert needle in _normalized_whitespace((REPO_ROOT / "setup.sh").read_text()), (
        f"setup.sh's auto-triage prompt no longer says {needle!r} — it must match "
        "Settings.auto_triage_min_severity."
    )
    assert needle in _normalized_whitespace(QUICKSTART_DOC.read_text()), (
        f"quickstart.md's install-step prose no longer says {needle!r} — it must "
        "match Settings.auto_triage_min_severity."
    )


# ---------------------------------------------------------------------------
# Gate 7 — CHANGELOG's "Config opens on N decisions" claim == the day1
# curation (Wave-2 progressive-disclosure review)
# ---------------------------------------------------------------------------
#
# The Config console's day-1 tier is a curated, tested set (see
# tests/test_config_day1_tier.py), and the Wave-2 CHANGELOG entry names the
# count in prose ("Config opens on seven decisions, not 109"). Nothing ties
# those two together: a future re-curation that adds or removes a day1 flag
# has no reason to touch CHANGELOG.md, so the shipped claim would keep
# reading "seven" after the real count moved. This gate derives the expected
# word straight from the live curation, so the direction of drift that
# matters — code changed, the shipped claim didn't — is what fails.

_NUMBER_WORDS = [
    "zero",
    "one",
    "two",
    "three",
    "four",
    "five",
    "six",
    "seven",
    "eight",
    "nine",
    "ten",
]


def test_changelog_day1_claim_matches_curation() -> None:
    """The changelog's 'Config opens on N decisions' line must track the real
    day1 curation — a re-curation that forgets the prose ships a false claim."""
    from soc_ai.store import config_overrides as cfg

    day1 = sum(1 for s in cfg.WHITELIST if s.day1)
    root = Path(__file__).resolve().parent.parent
    text = (root / "CHANGELOG.md").read_text().lower()
    assert f"config opens on {_NUMBER_WORDS[day1]} decisions" in text, (
        f"CHANGELOG's day-1 claim doesn't match the curated count ({day1})"
    )
