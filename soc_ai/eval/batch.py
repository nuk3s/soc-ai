"""Batch eval orchestrator.

Runs the single-alert eval harness over many alerts and writes a
streaming ``index.jsonl`` so a partial run is recoverable. Wraps each
``harness.run`` in a per-alert timeout, schedules under a bounded
semaphore, warms the prompt cache before fanning out, and
aborts if too many runs fail in a row.

The runner is the workhorse for ``soc-ai validate-batch``; a separate
:mod:`soc_ai.eval.report` module aggregates the resulting bundles.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import re
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING

from soc_ai.config import Settings
from soc_ai.eval.harness import EvalResult
from soc_ai.eval.harness import run as harness_run
from soc_ai.eval.sampler import DEFAULT_DIVERSITY_KEYS, sample_diverse_alerts
from soc_ai.eval.synth_ingest import IngestResult, ingest_scenarios
from soc_ai.so_client.elastic import ElasticClient

if TYPE_CHECKING:
    from soc_ai.eval.synth_loader import Scenario

_LOGGER = logging.getLogger(__name__)

# Match the three top-level Markdown sections the oracle is contracted to
# emit. Used by both the batch runner (to extract the agreement
# verdict) and the report aggregator (same regex, different caller).
_VERDICT_SECTION_RE = re.compile(
    r"^##\s*1\.\s*Verdict\s*\n(.*?)(?=^##\s|\Z)",
    re.IGNORECASE | re.MULTILINE | re.DOTALL,
)


@dataclass
class IndexRow:
    """One row of the streaming ``index.jsonl``.

    Fields populated only on success carry ``None`` on the error path.
    The ``error`` field is non-None iff the run failed.
    """

    alert_id: str
    bundle_path: str | None = None
    verdict: str | None = None
    confidence: float | None = None
    agreement: str | None = None  # "yes" | "no" | "partial" | "unknown"
    retask_count: int | None = None
    investigation_ms: int | None = None
    claude_ms: int | None = None
    input_tokens: int | None = None
    output_tokens: int | None = None
    cache_read_tokens: int | None = None
    error: str | None = None
    # Citations extracted from the triage report's `citations` list. Carried
    # here so synth_score._score_one can verify citation-kind coverage without
    # re-reading bundle files.
    citations: list[str] = field(default_factory=list)
    # synth-TP stratum tagging. False/None for real alerts;
    # set when the alert was ingested as a known synthetic-TP scenario.
    is_synth: bool = False
    synth_scenario_id: str | None = None


@dataclass
class BatchConfig:
    """Static config for one batch invocation."""

    oql: str
    n: int = 1000
    concurrency: int = 5
    diversity_keys: tuple[str, ...] = DEFAULT_DIVERSITY_KEYS
    time_range_minutes: int = 10_080  # 7 days
    out_dir: Path = field(default_factory=lambda: Path("evals"))
    resume: bool = False
    # Per-run wall-clock cap. Bumped from the original 900s after batch
    # runs saw most runs hitting the cap under concurrency=5 — the agent
    # loop's investigator + synthesizer plus the oracle call legitimately
    # need 12-25min on a contended GPU. 1800s (30 min) is the new default;
    # lower for speed-test environments, raise on heavily shared infra.
    per_run_timeout_s: int = 1800
    max_consecutive_failures: int = 10
    # pre-resolved list of scenarios to inject (None = no
    # synth). The CLI is responsible for parsing the --synth-set selector
    # into Scenario objects via synth_loader.select_scenarios.
    synth_scenarios: tuple[Scenario, ...] | None = None
    synth_run_time: datetime | None = None


@dataclass
class BatchSummary:
    """Returned to the CLI after the batch loop terminates."""

    batch_dir: Path
    n_planned: int
    n_attempted: int
    n_ok: int
    n_error: int
    aborted_reason: str | None
    elapsed_s: int


# Type alias so tests can substitute stubs without monkey-patching.
HarnessRunner = Callable[..., Awaitable[EvalResult]]
SamplerFn = Callable[..., AsyncIterator[str]]
SynthIngester = Callable[..., Awaitable[list[IngestResult]]]


_STRUCTURED_AGREEMENT_RE = re.compile(
    r"^\s*agreement\s*:\s*(yes|no|partial)\b", re.IGNORECASE | re.MULTILINE
)
# Strip markdown/bold/label prefixes so a leading "No" is still anchored.
_LEAD_PREFIX_RE = re.compile(
    r"^(?:[\s>#*_`~\-—:]+|(?:verdict|answer|assessment)\s*[:\-—]\s*)+",
    re.IGNORECASE,
)
_NEGATED_AGREE_RE = re.compile(
    # The curly apostrophes (U+2018/U+2019) are deliberate: oracle prose can
    # use smart quotes (isn + U+2019 + t correct), so the char class accepts
    # both typographic and ASCII apostrophes.
    r"\b(?:not|isn[‘’']?t|wasn[‘’']?t)\s+(?:\w+\s+){0,3}(?:correct|right|accurate)\b"  # noqa: RUF001
)


def extract_agreement(response_md: str) -> str:
    """Classify the oracle's verdict from a per-alert ``response.md``.

    Three-stage: first look for a machine-readable ``AGREEMENT: yes|no|partial``
    line (added to the oracle prompt), then fall back to
    format-tolerant prose heuristics for old bundles. Returns one of
    ``yes`` / ``no`` / ``partial`` / ``unknown``. Used by the batch runner
    for the streaming ``agreement`` field on each :class:`IndexRow`; the
    report aggregator reuses this same function so the contract stays in
    one place.

    The classifier is deliberately conservative — ``unknown`` rather
    than guessing — because ``unknown`` shows up cleanly in
    ``aggregates.json`` as a signal that the per-alert prompt's
    instruction to start with the verdict isn't sticking.
    """
    if not response_md:
        return "unknown"
    m = _VERDICT_SECTION_RE.search(response_md)
    body = (m.group(1) if m else response_md).strip().lower()
    # Look at the first paragraph only — "I disagree, but partially..."
    # would otherwise fight itself.
    first_para = body.split("\n\n", 1)[0].strip()

    # Stage 1: structured AGREEMENT line wins immediately.
    sm = _STRUCTURED_AGREEMENT_RE.search(body)
    if sm:
        return sm.group(1).lower()

    # Stage 2: format-tolerant prose heuristics.
    # Strip markdown/bold/label prefixes before anchoring the leading word,
    # so "**Verdict:** No" resolves correctly.
    lead = _LEAD_PREFIX_RE.sub("", first_para[:60])
    # Order matters: `partial` first (least ambiguous), then disagreement
    # (a leading "no", explicit disagreement verb, or negated agreement word),
    # then agreement. Negation check is BEFORE the yes-branch so a plain
    # "correct|right|accurate" check is safe without a lookbehind.
    if re.search(r"\bpartial(?:ly)?\b", first_para):
        return "partial"
    if (
        re.match(r"no\b", lead)
        # `disagree(s|d)` is the decisive disagreement signal. `incorrect`/`wrong`
        # were dropped: they misfire on "not incorrect" / "conclusion isn't wrong"
        # (a double negation that actually means agreement). _NEGATED_AGREE_RE
        # still catches the negated-agreement forms.
        or re.search(r"\b(?:disagree(?:s|d)?)\b", first_para)
        or _NEGATED_AGREE_RE.search(first_para)
    ):
        return "no"
    if (
        re.match(r"yes\b", lead)
        or re.search(r"\bagree(?:s|d)?\b", first_para)
        or re.search(r"\b(?:correct|right|accurate)\b", first_para)
    ):
        return "yes"
    return "unknown"


def read_retask_count(bundle_dir: Path) -> int:
    """Count ``retask`` SSE events in a bundle's ``events.jsonl``.

    Defensive against missing/corrupt files: returns 0 on any failure
    so a malformed bundle doesn't poison the aggregate.
    """
    path = bundle_dir / "events.jsonl"
    if not path.exists():
        return 0
    count = 0
    try:
        with path.open(encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if ev.get("kind") == "retask":
                    count += 1
    except OSError:
        return 0
    return count


def _index_path(batch_dir: Path) -> Path:
    return batch_dir / "index.jsonl"


def _read_completed_alert_ids(batch_dir: Path) -> set[str]:
    """Return the set of alert IDs already written to ``index.jsonl``.

    Used by ``--resume`` to skip alerts a previous (interrupted) run
    completed. Errored runs are NOT skipped — the operator may want
    them re-tried.
    """
    path = _index_path(batch_dir)
    if not path.exists():
        return set()
    completed: set[str] = set()
    with path.open(encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("error"):
                continue
            aid = row.get("alert_id")
            if aid:
                completed.add(aid)
    return completed


def _append_index_row(batch_dir: Path, row: IndexRow) -> None:
    with _index_path(batch_dir).open("a", encoding="utf-8") as f:
        f.write(json.dumps(asdict(row), default=str))
        f.write("\n")


def _new_batch_dir(parent: Path) -> Path:
    """Build a fresh ``<parent>/batch-<utc-ts>`` directory."""
    ts = datetime.now(UTC).strftime("%Y-%m-%dT%H%M%SZ")
    out = parent / f"batch-{ts}"
    out.mkdir(parents=True, exist_ok=True)
    return out


def _format_progress(
    done: int,
    total: int,
    n_ok: int,
    n_err: int,
    started: float,
    last_verdict: str | None,
) -> str:
    elapsed = int(time.monotonic() - started)
    h, rem = divmod(elapsed, 3600)
    m, s = divmod(rem, 60)
    rate = (done / elapsed) if elapsed > 0 else 0.0
    return (
        f"{done}/{total} · ok={n_ok} · err={n_err} · "
        f"last_verdict={last_verdict or '-'} · "
        f"elapsed={h:d}h{m:02d}m{s:02d}s · {rate:.2f}/s"
    )


async def _run_one(
    alert_id: str,
    *,
    settings: Settings,
    batch_dir: Path,
    runner: HarnessRunner,
    timeout_s: int,
    synth_scenario_id: str | None = None,
    expected_verdict: str | None = None,
) -> IndexRow:
    """Run the harness for one alert; build the IndexRow either way."""
    is_synth = synth_scenario_id is not None
    try:
        result = await asyncio.wait_for(
            # Triaging a synth alert: let the prefetch see this scenario's own
            # supporting docs (real alerts keep the prod-default exclusion).
            # Pass the planted expected_verdict so the oracle grades factually.
            runner(
                alert_id,
                settings=settings,
                out_dir=batch_dir,
                include_synth=is_synth,
                expected_verdict=expected_verdict,
            ),
            timeout=timeout_s,
        )
    except TimeoutError:
        return IndexRow(
            alert_id=alert_id,
            error=f"timeout after {timeout_s}s",
            is_synth=is_synth,
            synth_scenario_id=synth_scenario_id,
        )
    except Exception as e:
        return IndexRow(
            alert_id=alert_id,
            error=f"{type(e).__name__}: {e}"[:500],
            is_synth=is_synth,
            synth_scenario_id=synth_scenario_id,
        )

    bundle_dir = result.bundle_dir
    response_md = (bundle_dir / "response.md").read_text(encoding="utf-8")
    agreement = extract_agreement(response_md)
    retask_count = read_retask_count(bundle_dir)
    report = result.sanitized_report or {}
    usage = result.oracle_response.usage

    return IndexRow(
        alert_id=alert_id,
        bundle_path=str(bundle_dir),
        verdict=report.get("verdict"),
        confidence=report.get("confidence"),
        agreement=agreement,
        retask_count=retask_count,
        investigation_ms=result.investigation_elapsed_ms,
        claude_ms=result.oracle_response.elapsed_ms,
        input_tokens=usage.get("input_tokens"),
        output_tokens=usage.get("output_tokens"),
        cache_read_tokens=usage.get("cache_read_input_tokens"),
        citations=list(report.get("citations") or []),
        error=None,
        is_synth=is_synth,
        synth_scenario_id=synth_scenario_id,
    )


async def run_batch(  # noqa: PLR0912, PLR0915 - one place that wires the whole loop
    cfg: BatchConfig,
    *,
    settings: Settings,
    elastic: ElasticClient,
    sampler: SamplerFn = sample_diverse_alerts,
    runner: HarnessRunner = harness_run,
    synth_ingester: SynthIngester = ingest_scenarios,
    progress: Callable[[str], None] | None = None,
) -> BatchSummary:
    """Drive a batch eval end-to-end.

    Args:
        cfg: per-batch parameters (OQL, n, concurrency, …).
        settings: app settings; LITELLM_API_KEY required.
        elastic: shared ES client used by the sampler. The per-run
            harness still owns its own ES client (one per call) — this
            one is just for the upfront sampling query.
        sampler: pluggable sampler (tests substitute a fixed list).
        runner: pluggable harness (tests substitute a stub returning
            canned ``EvalResult`` instances or raising on demand).
        progress: optional callback for live progress strings (default
            prints to stderr via the caller).

    Returns:
        :class:`BatchSummary` describing how many ran and why we
        stopped (success / failure budget / sampler exhaustion).
    """
    if not settings.litellm_api_key:
        raise RuntimeError(
            "LITELLM_API_KEY not set; can't run batch (the per-alert "
            "oracle call would 401 against the gateway). Set it in "
            "/opt/soc-ai/.env."
        )

    batch_dir = cfg.out_dir if cfg.resume and cfg.out_dir.exists() else _new_batch_dir(cfg.out_dir)
    completed = _read_completed_alert_ids(batch_dir) if cfg.resume else set()
    if completed:
        _LOGGER.info("resume: skipping %d already-completed alert IDs", len(completed))

    started = time.monotonic()

    # Materialize the diverse alert list. (We pull once rather than
    # streaming so a sampler crash doesn't leave us mid-batch.)
    target_ids: list[str] = []
    async for aid in sampler(
        cfg.oql,
        n=cfg.n,
        settings=settings,
        elastic=elastic,
        diversity_keys=cfg.diversity_keys,
        time_range_minutes=cfg.time_range_minutes,
    ):
        if aid in completed:
            continue
        target_ids.append(aid)

    # inject synth-TP scenarios. Pre-ingest them so the
    # harness's prefetch can read them back via OpenSearch the same way
    # it reads real alerts. Then mix the triage doc IDs into target_ids
    # and remember which ones came from which scenario for IndexRow tagging.
    synth_id_to_scenario: dict[str, str] = {}
    # Maps triage_doc_id → expected_verdict so the oracle prompt for synth
    # rows gets the planted ground truth.
    synth_id_to_expected_verdict: dict[str, str] = {}
    if cfg.synth_scenarios:
        scenario_by_id = {s.id: s for s in cfg.synth_scenarios}
        run_time = cfg.synth_run_time or datetime.now(UTC)
        ingest_results = await synth_ingester(
            list(cfg.synth_scenarios), elastic=elastic, run_time=run_time
        )
        for res in ingest_results:
            if res.triage_doc_id in completed:
                continue
            synth_id_to_scenario[res.triage_doc_id] = res.scenario_id
            scenario = scenario_by_id.get(res.scenario_id)
            if scenario is not None and scenario.ground_truth is not None:
                synth_id_to_expected_verdict[res.triage_doc_id] = scenario.ground_truth.verdict
            target_ids.append(res.triage_doc_id)

    if not target_ids:
        return BatchSummary(
            batch_dir=batch_dir,
            n_planned=0,
            n_attempted=0,
            n_ok=0,
            n_error=0,
            aborted_reason="sampler returned no eligible alerts",
            elapsed_s=int(time.monotonic() - started),
        )

    sem = asyncio.Semaphore(cfg.concurrency)
    n_ok = 0
    n_err = 0
    consecutive_failures = 0
    aborted_reason: str | None = None
    last_verdict: str | None = None
    cancelled = False

    async def _bounded(alert_id: str) -> IndexRow:
        async with sem:
            scenario_id = synth_id_to_scenario.get(alert_id)
            if cancelled:
                return IndexRow(
                    alert_id=alert_id,
                    error="aborted by failure budget",
                    is_synth=scenario_id is not None,
                    synth_scenario_id=scenario_id,
                )
            return await _run_one(
                alert_id,
                settings=settings,
                batch_dir=batch_dir,
                runner=runner,
                timeout_s=cfg.per_run_timeout_s,
                synth_scenario_id=scenario_id,
                expected_verdict=synth_id_to_expected_verdict.get(alert_id),
            )

    # ---- Cache-warmup: run the first alert sequentially so the
    # prompt cache becomes resident before we fan out.
    # On a flat-fee plan the savings are speed, not money. ~30s spent
    # here recovers ~1.5M cached tokens of throughput per concurrent
    # follower over the rest of the batch.
    warmup_id = target_ids[0]
    rest_ids = target_ids[1:]
    warmup_row = await _run_one(
        warmup_id,
        settings=settings,
        batch_dir=batch_dir,
        runner=runner,
        timeout_s=cfg.per_run_timeout_s,
        synth_scenario_id=synth_id_to_scenario.get(warmup_id),
        expected_verdict=synth_id_to_expected_verdict.get(warmup_id),
    )
    _append_index_row(batch_dir, warmup_row)
    if warmup_row.error:
        n_err += 1
        consecutive_failures = 1
    else:
        n_ok += 1
        last_verdict = warmup_row.verdict
    if progress:
        progress(_format_progress(1, len(target_ids), n_ok, n_err, started, last_verdict))

    # ---- Fan out the remaining alerts.
    tasks = [asyncio.create_task(_bounded(aid)) for aid in rest_ids]
    done_count = 1
    for fut in asyncio.as_completed(tasks):
        row = await fut
        _append_index_row(batch_dir, row)
        done_count += 1
        if row.error:
            n_err += 1
            consecutive_failures += 1
            if consecutive_failures >= cfg.max_consecutive_failures:
                aborted_reason = (
                    f"aborted: {consecutive_failures} consecutive failures "
                    f"(threshold={cfg.max_consecutive_failures})"
                )
                cancelled = True
                for t in tasks:
                    if not t.done():
                        t.cancel()
                break
        else:
            n_ok += 1
            consecutive_failures = 0
            last_verdict = row.verdict

        if progress:
            progress(
                _format_progress(
                    done_count,
                    len(target_ids),
                    n_ok,
                    n_err,
                    started,
                    last_verdict,
                )
            )

    # Drain any cancelled tasks so we don't get noisy warnings.
    if cancelled:
        for t in tasks:
            if t.cancelled() or t.done():
                continue
            with contextlib.suppress(asyncio.CancelledError, Exception):
                await t

    return BatchSummary(
        batch_dir=batch_dir,
        n_planned=len(target_ids),
        n_attempted=n_ok + n_err,
        n_ok=n_ok,
        n_error=n_err,
        aborted_reason=aborted_reason,
        elapsed_s=int(time.monotonic() - started),
    )
