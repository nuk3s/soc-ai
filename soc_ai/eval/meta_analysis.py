"""Oracle meta-analysis: cluster per-alert critiques into top-N changes.

1000 critiques × ~5K tokens = ~5M tokens — doesn't fit in Opus 1M
context, and even if it did, signal would drown. The strategy here is
**map-reduce focused on the ``## 3. Architecture`` slice** of each
per-alert response:

- **Map step (parallel):** chunk runs into groups of ~25; for each
  chunk, send only the `## 3. Architecture` slice + per-alert
  verdict/agreement/retask. Ask the oracle to cluster the suggestions
  into themes.
- **Disagreement carve-out:** runs where the oracle said `agreement="no"`
  also include the full `## 2. Why` section in their chunk —
  disagreements are rare (target ≤10%) and carry the highest signal.
- **Reduce step:** feed `aggregates.json` + the chunk theme summaries
  and ask the oracle for the **5 highest-impact architecture changes**,
  defined operationally as: improves agreement_rate, reduces
  retask_rate, or cuts p95 latency.

Distinct system prompt: emphasizes that the input is summaries-of-
summaries and the output is *change recommendations* not *individual
alert critique*. Without this framing the model defaults to per-alert
observations.

Output: ``meta_analysis.md`` (human read) + ``meta_analysis.json``
(top-5 structured for downstream tooling).
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from soc_ai.config import Settings
from soc_ai.eval import sanitize as san
from soc_ai.eval.oracle_client import OracleError, OracleResponse, call_oracle

_LOGGER = logging.getLogger(__name__)

# Number of runs per map chunk. ~25 critiques × ~1.5K architecture
# tokens ≈ 40K — well under Opus 1M ctx, leaves headroom for the
# disagreement carve-out.
_MAP_CHUNK_SIZE = 25

# Bound on parallel map calls. The gateway handles the load fine;
# 3 keeps cache hits warm without overwhelming the upstream.
_MAP_CONCURRENCY = 3

# Match top-level Markdown sections in a per-alert response.md.
# Tolerates extra whitespace and different cases.
_SECTION_RE = re.compile(
    r"^##\s*{n}\.\s*[^\n]*\n(.*?)(?=^##\s|\Z)",
    re.IGNORECASE | re.MULTILINE | re.DOTALL,
)

META_SYSTEM_PROMPT = """\
You are doing a META-analysis of a Security Onion triage agent's
batch eval results. The input you'll receive is NOT a per-alert
investigation — it is a chunk of *already-summarized* per-alert
critiques (specifically the architecture-recommendations sections
from each critique, plus a few stats per alert).

Your job is to synthesize ARCHITECTURE-LEVEL change recommendations
for the soc-ai agent — not to critique any one alert. Cluster
suggestions across alerts; identify themes that appear in many runs;
ignore one-off complaints unless they correlate with a specific
failure mode (e.g. all the disagreements share a missing tool).

"High impact" is defined operationally as a change that would:
- improve `agreement_rate` (the oracle agrees with the agent's verdict),
- reduce `retask_rate` (how often the tool-less round-1 synthesis had
  to name a gap for a Phase-D targeted dispatch — i.e. the prefetched
  evidence didn't settle the verdict on its own),
- cut p95 latency on `investigation_ms`.

Be specific and concrete. "Improve prompts" is useless; "tighten the
investigation loop's stop condition to 'evidence + community_id pivot +
one enrichment is enough'" is actionable.

When you produce JSON output, output the JSON DIRECTLY — no preamble,
no ```json fences. The caller machine-parses your response.
"""


@dataclass
class RunSlim:
    """A per-alert row trimmed to what the meta-analysis actually reads."""

    alert_id: str
    verdict: str | None
    agreement: str
    retask_count: int
    architecture_section: str
    # Populated only when agreement == "no" (disagreements get the full
    # `## 2. Why` so themes carry the *reason* the oracle pushed back).
    why_section: str | None = None


@dataclass
class MapTheme:
    """One theme returned from a single map-chunk call."""

    theme: str
    count_in_chunk: int
    representative_quote: str
    expected_impact: str
    supporting_alert_ids: list[str] = field(default_factory=list)


@dataclass
class ArchitectureChange:
    """One of the top-5 changes returned from the reduce step."""

    change: str
    description: str
    evidence: str
    expected_lift: str
    risk: str
    priority: str  # "high" | "medium" | "low"


@dataclass
class MetaResult:
    """End-to-end output of one meta-analysis run."""

    md_path: Path
    json_path: Path
    n_chunks: int
    n_runs_in_meta: int
    n_themes_total: int
    changes: list[ArchitectureChange]
    map_response_ms_total: int
    reduce_response_ms: int


# Pluggable callable type — sync, like ``call_oracle`` itself; the
# orchestrator wraps each call in ``asyncio.to_thread`` so map-reduce
# concurrency works without a separate async client.
OracleCallable = Callable[..., OracleResponse]


# --------------------------------------------------------------------
# Section extraction
# --------------------------------------------------------------------


def extract_section(response_md: str, n: int) -> str | None:
    """Return the body of the ``## N. <title>`` section, or None."""
    if not response_md:
        return None
    pat = re.compile(
        _SECTION_RE.pattern.replace("{n}", str(n)),
        _SECTION_RE.flags,
    )
    m = pat.search(response_md)
    return m.group(1).strip() if m else None


def load_slim_rows(rows: list[dict[str, Any]]) -> list[RunSlim]:
    """Read each successful run's bundle and pull the slim fields.

    Reads the SANITIZED (label-only) critique copy, never the de-sanitized
    ``response.md``: the meta hop re-sends these sections to the cloud oracle,
    so it must not rehydrate real internal identifiers back into the payload
    (F01). Skips errored rows, rows with no bundle, and legacy bundles that
    predate ``response.sanitized.md`` — falling back to ``response.md`` there
    would reintroduce the leak. Disagreements (`agreement="no"`) also load the
    `## 2. Why` section.
    """
    slim: list[RunSlim] = []
    for r in rows:
        if r.get("error"):
            continue
        bp = r.get("bundle_path")
        if not bp:
            continue
        bundle = Path(bp)
        response_path = bundle / "response.sanitized.md"
        if not response_path.exists():
            _LOGGER.warning(
                "meta: bundle %s has no response.sanitized.md; skipping "
                "(will not fall back to the de-sanitized response.md)",
                bundle,
            )
            continue
        try:
            md = response_path.read_text(encoding="utf-8")
        except OSError as e:
            _LOGGER.warning("meta: can't read %s: %s", response_path, e)
            continue
        agreement = r.get("agreement") or "unknown"
        arch = extract_section(md, 3) or ""
        why = extract_section(md, 2) if agreement == "no" else None
        slim.append(
            RunSlim(
                alert_id=str(r.get("alert_id") or "?"),
                verdict=r.get("verdict"),
                agreement=agreement,
                retask_count=int(r.get("retask_count") or 0),
                architecture_section=arch,
                why_section=why,
            )
        )
    return slim


def chunk_runs(slim: list[RunSlim], chunk_size: int = _MAP_CHUNK_SIZE) -> list[list[RunSlim]]:
    """Split into chunks of ``chunk_size`` (last may be shorter)."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    return [slim[i : i + chunk_size] for i in range(0, len(slim), chunk_size)]


# --------------------------------------------------------------------
# Prompt builders
# --------------------------------------------------------------------


def build_map_prompt(chunk: list[RunSlim]) -> str:
    """Build the user message for one map-chunk call.

    Format: per-alert sections for each run, then the clustering
    instructions. The disagreements include their `## 2. Why` so the
    model can root-cause the failure mode, not just the suggested fix.
    """
    parts: list[str] = [
        "# Map step: cluster architecture suggestions across this chunk\n",
        f"This chunk contains {len(chunk)} alert eval result(s). Each entry "
        "below carries one alert's `## 3. Architecture` section verbatim "
        "(suggestions the oracle already made about how to improve soc-ai), "
        "plus per-alert verdict / agreement / retask stats. For runs where "
        "the oracle DISAGREED with the agent's verdict (`agreement=no`), the "
        "full `## 2. Why` section is also included since disagreements "
        "carry the highest signal about systemic failure modes.\n",
    ]
    for run in chunk:
        parts.append(f"\n---\n\n## Alert `{run.alert_id}`\n")
        parts.append(
            f"- verdict: `{run.verdict}` · agreement: `{run.agreement}` · "
            f"retask_count: {run.retask_count}\n"
        )
        if run.why_section:
            parts.append("\n### Why the oracle disagreed (verbatim)\n\n")
            parts.append(run.why_section + "\n")
        parts.append("\n### Architecture suggestions (verbatim)\n\n")
        parts.append(run.architecture_section.strip() or "_(empty section)_")
        parts.append("\n")

    parts.append(
        "\n---\n\n# Task\n\n"
        "Cluster the architecture suggestions above into THEMES. Each "
        "theme should be a specific, named architectural change "
        '(e.g., `"investigation loop: tighten stop condition"`, `"tool '
        'surface: add zeek http_status pivot"`, `"phase-d dispatch: '
        'trigger on missing-enrichment, not only a synth-named gap"`).\n\n'
        "Return a JSON array. Each element MUST have these keys:\n\n"
        "- `theme`: short name (~6 words).\n"
        "- `count_in_chunk`: integer, how many alerts in this chunk "
        "raised this theme.\n"
        "- `representative_quote`: one short verbatim quote that "
        "captures the theme's wording.\n"
        '- `expected_impact`: one of `"agreement_rate"`, '
        '`"retask_rate"`, `"latency"`, or `"uncertain"`.\n'
        "- `supporting_alert_ids`: list of alert IDs in THIS chunk "
        "that mentioned the theme.\n\n"
        "Aim for 3-8 themes per chunk. Drop one-off comments that "
        "don't appear in multiple alerts UNLESS the comment came from "
        "a `agreement=no` run, in which case keep it (those are the "
        "highest-signal cases).\n\n"
        "Output the JSON array directly. No preamble, no ```json "
        "fences."
    )
    return "".join(parts)


def build_reduce_prompt(
    aggregates: dict[str, Any],
    map_results: list[list[dict[str, Any]]],
) -> str:
    """Build the user message for the single reduce call."""
    flat_themes = [t for chunk in map_results for t in chunk]
    return (
        "# Reduce step: top-5 architecture changes for soc-ai\n\n"
        "## Aggregate stats for this batch\n\n"
        "```json\n"
        f"{json.dumps(aggregates, indent=2, default=str)}\n"
        "```\n\n"
        f"## Themes from {len(map_results)} map chunks "
        f"({len(flat_themes)} themes total)\n\n"
        "```json\n"
        f"{json.dumps(flat_themes, indent=2, default=str)}\n"
        "```\n\n"
        "# Task\n\n"
        "Pick the **5 highest-impact** architecture changes for "
        "soc-ai. Use the aggregate stats AND the cluster themes; "
        "favor themes with high `count_in_chunk` summed across "
        "chunks, themes that show up in multiple disagreements, and "
        "themes whose `expected_impact` matches a metric the "
        "aggregates show is weak (e.g., low `agreement_rate`, high "
        "`retask_rate`, high p95 `investigation_ms`).\n\n"
        "For each change, return a JSON object with:\n\n"
        "- `change`: short name (~8 words).\n"
        "- `description`: 2-4 sentences on the concrete edit "
        "(prompt change / new tool / flow tweak / dispatch or "
        "loop-entry trigger / etc).\n"
        "- `evidence`: cite specific theme names and counts and "
        "aggregate signals.\n"
        "- `expected_lift`: which of agreement_rate / retask_rate / "
        "p95 latency this moves, and direction.\n"
        "- `risk`: what could go wrong with this change.\n"
        '- `priority`: one of `"high"`, `"medium"`, `"low"`.\n\n'
        'Output a JSON object: `{"changes": [...]}` with EXACTLY 5 '
        "entries in the array.\n\n"
        "Then add a Markdown narrative AFTER the JSON, separated by "
        "a `---` line, that summarizes the top change, calls out any "
        "tempting-but-low-priority changes you skipped and why, and "
        "flags any aggregate signal that the themes don't explain.\n"
    )


# --------------------------------------------------------------------
# JSON extraction (defensive against fences / preamble)
# --------------------------------------------------------------------


def _strip_fences(text: str) -> str:
    """Remove ```json ... ``` fences if the oracle added them despite the
    explicit "no fences" instruction. Returns the inner text."""
    text = text.strip()
    fence_pat = re.compile(r"^```(?:json)?\s*\n(.*?)\n```\s*$", re.DOTALL)
    m = fence_pat.match(text)
    return m.group(1).strip() if m else text


def parse_map_response(text: str) -> list[dict[str, Any]]:
    """Parse one map call's response into a list of theme dicts.

    Returns ``[]`` and logs a warning on any parse failure rather than
    crashing — a single bad chunk shouldn't kill the whole reduce step.
    """
    try:
        parsed = json.loads(_strip_fences(text))
    except json.JSONDecodeError as e:
        _LOGGER.warning("meta: map response not JSON (%s); skipping chunk", e)
        return []
    if not isinstance(parsed, list):
        _LOGGER.warning(
            "meta: map response is %s, expected list; skipping chunk",
            type(parsed).__name__,
        )
        return []
    return [t for t in parsed if isinstance(t, dict)]


def parse_reduce_response(text: str) -> tuple[list[ArchitectureChange], str]:
    """Parse the reduce response into (changes, narrative_md).

    The reduce prompt asks for `{"changes": [...]}` followed by `---`
    and a Markdown narrative. We extract the JSON object, ignore any
    leading prose, and treat everything after `---` (or after the
    JSON object) as the narrative.
    """
    raw = text.strip()
    # Find the first `{` and the matching closing `}` for the changes
    # object. JSON blocks may be fenced; strip those first.
    candidate = _strip_fences(raw)
    json_start = candidate.find("{")
    if json_start < 0:
        return [], raw

    decoder = json.JSONDecoder()
    try:
        parsed, end = decoder.raw_decode(candidate[json_start:])
    except json.JSONDecodeError as e:
        _LOGGER.warning("meta: reduce JSON parse failed (%s)", e)
        return [], raw
    if not isinstance(parsed, dict) or "changes" not in parsed:
        _LOGGER.warning("meta: reduce JSON missing `changes` key")
        return [], raw

    changes_raw = parsed["changes"]
    if not isinstance(changes_raw, list):
        return [], raw

    changes: list[ArchitectureChange] = []
    for c in changes_raw:
        if not isinstance(c, dict):
            continue
        try:
            changes.append(
                ArchitectureChange(
                    change=str(c.get("change", "")),
                    description=str(c.get("description", "")),
                    evidence=str(c.get("evidence", "")),
                    expected_lift=str(c.get("expected_lift", "")),
                    risk=str(c.get("risk", "")),
                    priority=str(c.get("priority", "")),
                )
            )
        except (KeyError, TypeError):
            continue

    # Narrative: everything after the JSON block. Strip the leading
    # `---` separator if present.
    tail = candidate[json_start + end :].lstrip()
    tail = re.sub(r"^---+\s*\n?", "", tail).strip()
    return changes, tail


# --------------------------------------------------------------------
# Orchestration
# --------------------------------------------------------------------


async def _call_oracle_async(
    *,
    settings: Settings,
    user_message: str,
    oracle_caller: OracleCallable,
) -> OracleResponse:
    """Wrap the sync ``call_oracle`` in to_thread for use in gather()."""
    # Defense in depth (F01): the map/reduce prompt is built from the label-only
    # response.sanitized.md, so it should already be clean — but re-run the
    # residue sweep before egress anyway, mirroring the per-alert harness's
    # pre-send gate. A sanitizer gap or a hallucinated internal identifier must
    # not slip to the cloud on this second hop.
    issues = san.unsafe_residue(
        user_message,
        extra_hosts=settings.oracle_extra_hosts,
        extra_suffixes=settings.oracle_internal_suffixes,
    )
    if issues:
        raise RuntimeError(
            f"meta-analysis residue check refused to send ({len(issues)} issues): "
            + "; ".join(issues[:5])
        )
    api_key = (
        settings.litellm_api_key.get_secret_value() if settings.litellm_api_key is not None else ""
    )
    return await asyncio.to_thread(
        oracle_caller,
        base_url=str(settings.litellm_base_url),
        api_key=api_key,
        verify_ssl=settings.litellm_verify_ssl,
        model=settings.claude_oracle_model,
        max_tokens=settings.claude_oracle_max_tokens,
        system_prompt=META_SYSTEM_PROMPT,
        arch_context=None,  # meta path doesn't need agent prompts in ctx
        user_message=user_message,
    )


async def run_meta_analysis(
    *,
    rows: list[dict[str, Any]],
    batch_dir: Path,
    aggregates: dict[str, Any],
    settings: Settings,
    oracle_caller: OracleCallable = call_oracle,
    map_concurrency: int = _MAP_CONCURRENCY,
    map_chunk_size: int = _MAP_CHUNK_SIZE,
) -> MetaResult:
    """Run the map-reduce meta-analysis end-to-end.

    Args:
        rows: index.jsonl rows for the batch.
        batch_dir: where ``meta_analysis.{md,json}`` will be written.
        aggregates: the JSON-friendly dict from
            :func:`soc_ai.eval.report.aggregates_to_json`.
        settings: app settings (LITELLM_* must be set).
        oracle_caller: pluggable oracle call (tests stub).
        map_concurrency: parallel map calls.
        map_chunk_size: runs per chunk.

    Returns:
        :class:`MetaResult` describing what was written.
    """
    if not settings.litellm_api_key:
        raise RuntimeError("LITELLM_API_KEY not set; cannot run meta-analysis.")

    slim = load_slim_rows(rows)
    if not slim:
        raise RuntimeError("no usable runs for meta-analysis (all errored or no bundles)")

    chunks = chunk_runs(slim, map_chunk_size)
    _LOGGER.info(
        "meta: %d runs in %d chunks of size %d (concurrency=%d)",
        len(slim),
        len(chunks),
        map_chunk_size,
        map_concurrency,
    )

    # ---- Map step
    sem = asyncio.Semaphore(map_concurrency)

    async def _map_one(chunk: list[RunSlim]) -> tuple[list[dict[str, Any]], int]:
        async with sem:
            try:
                resp = await _call_oracle_async(
                    settings=settings,
                    user_message=build_map_prompt(chunk),
                    oracle_caller=oracle_caller,
                )
            except OracleError as e:
                _LOGGER.warning("meta: map call failed (%s); skipping chunk", e)
                return [], 0
            return parse_map_response(resp.text), resp.elapsed_ms

    map_results_with_times = await asyncio.gather(*[_map_one(c) for c in chunks])
    map_results = [r for r, _ in map_results_with_times]
    map_response_ms_total = sum(t for _, t in map_results_with_times)
    n_themes_total = sum(len(t) for t in map_results)

    # Guard: refuse to hallucinate a reduce over empty evidence.
    if n_themes_total == 0:
        raise RuntimeError(
            "meta-analysis: all map chunks failed or produced no themes — "
            "refusing to run reduce on empty evidence"
        )

    # ---- Reduce step
    try:
        reduce_resp = await _call_oracle_async(
            settings=settings,
            user_message=build_reduce_prompt(aggregates, map_results),
            oracle_caller=oracle_caller,
        )
    except OracleError as e:
        raise RuntimeError(f"meta-analysis reduce step failed: {e}") from e

    changes, narrative = parse_reduce_response(reduce_resp.text)

    # ---- Persist
    md_path, json_path = _write_meta_outputs(
        batch_dir,
        changes=changes,
        narrative=narrative,
        raw_response=reduce_resp.text,
        n_themes=n_themes_total,
        n_runs=len(slim),
        n_chunks=len(chunks),
    )

    return MetaResult(
        md_path=md_path,
        json_path=json_path,
        n_chunks=len(chunks),
        n_runs_in_meta=len(slim),
        n_themes_total=n_themes_total,
        changes=changes,
        map_response_ms_total=map_response_ms_total,
        reduce_response_ms=reduce_resp.elapsed_ms,
    )


# --------------------------------------------------------------------
# Persistence
# --------------------------------------------------------------------


def _write_meta_outputs(
    batch_dir: Path,
    *,
    changes: list[ArchitectureChange],
    narrative: str,
    raw_response: str,
    n_themes: int,
    n_runs: int,
    n_chunks: int,
) -> tuple[Path, Path]:
    """Write meta_analysis.md (Markdown) + meta_analysis.json (structured)."""
    md = _render_meta_markdown(
        changes=changes,
        narrative=narrative,
        n_themes=n_themes,
        n_runs=n_runs,
        n_chunks=n_chunks,
    )
    md_path = batch_dir / "meta_analysis.md"
    md_path.write_text(md, encoding="utf-8")

    json_path = batch_dir / "meta_analysis.json"
    json_path.write_text(
        json.dumps(
            {
                "n_runs_in_meta": n_runs,
                "n_chunks": n_chunks,
                "n_themes_total": n_themes,
                "changes": [asdict(c) for c in changes],
                "raw_reduce_response": raw_response,
            },
            indent=2,
            default=str,
        ),
        encoding="utf-8",
    )
    return md_path, json_path


def _render_meta_markdown(
    *,
    changes: list[ArchitectureChange],
    narrative: str,
    n_themes: int,
    n_runs: int,
    n_chunks: int,
) -> str:
    """Render the human-readable meta-analysis."""
    sections: list[str] = [
        "# Meta-analysis: top architecture changes\n",
        f"Synthesized from {n_runs} per-alert critiques across "
        f"{n_chunks} map chunk(s) yielding {n_themes} themes.\n",
    ]
    if not changes:
        sections.append(
            "\n_Reduce step did not return parseable structured "
            "changes; raw response saved to `meta_analysis.json`._\n"
        )
    else:
        sections.append("## Top changes\n")
        for i, c in enumerate(changes, 1):
            sections.append(
                f"\n### {i}. {c.change} _(priority: **{c.priority}**)_\n\n"
                f"**Description.** {c.description}\n\n"
                f"**Evidence.** {c.evidence}\n\n"
                f"**Expected lift.** {c.expected_lift}\n\n"
                f"**Risk.** {c.risk}\n"
            )
    if narrative:
        sections.append("\n## Narrative\n\n")
        sections.append(narrative.strip() + "\n")
    return "\n".join(sections)
