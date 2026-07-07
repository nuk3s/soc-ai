"""Lightweight Prometheus exposition for soc-ai.

Avoids the ``prometheus_client`` dependency to keep the install slim;
emits Prometheus 0.0.4 plain-text format from scratch. The metric set
is intentionally small — only the operationally-interesting counters
the orchestrator already tracks. Add new metrics as they justify
themselves.

Counters / gauges exposed:

- ``socai_build_info`` (gauge, labeled by ``version``) — always 1.
- ``socai_investigations_total`` — number of /investigate requests
  the orchestrator has fully streamed (any verdict).
- ``socai_investigation_errors_total`` — investigations that yielded
  any ``error`` event.
- ``socai_investigation_retasks_total`` — investigations where the
  retask round fired (synthesis confidence below floor).
- ``socai_investigation_fallback_verdicts_total`` — investigations
  where a synthesis-failure fallback (synthetic/M27) report was
  emitted. Watch this stays under 5% of investigations.
- ``socai_investigation_zero_tool_verdicts_total`` — zero-tool TP/FP
  verdicts blocked/coerced by the evidence gate (QVOD early-warning).
- ``socai_tool_calls_total`` (labeled by ``tool``) — per-tool call
  counts, for spotting which read tools are hot or broken.
- ``socai_llm_tokens_total`` (labeled by ``phase``, ``direction``) —
  cumulative token usage; ``direction`` is ``input`` / ``output``.

The orchestrator's ``audit`` plumbing already produces every input;
we just keep a small in-process counter set that ``/metrics``
serializes on demand. No persistence — counters reset on restart,
which is appropriate for Prometheus's pull model (each scrape is a
delta against the previous one, computed by Prometheus itself).
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict
from typing import Any


class _Metrics:
    """In-process metric counter set. Thread-safe under the asyncio loop."""

    def __init__(self) -> None:
        self.lock = asyncio.Lock()
        self.investigations_total = 0
        self.investigation_errors_total = 0
        self.investigation_retasks_total = 0
        self.investigation_fallback_verdicts_total = 0
        self.investigation_zero_tool_verdicts_total = 0
        self.tool_calls_total: dict[str, int] = defaultdict(int)
        # (phase, direction) -> tokens
        self.llm_tokens_total: dict[tuple[str, str], int] = defaultdict(int)
        self.start_time = time.time()

    async def record_event(self, kind: str, payload: dict[str, Any]) -> None:
        """Update counters from a single SSE event payload."""
        async with self.lock:
            if kind == "tool_call":
                tool = payload.get("tool_name") or "unknown"
                self.tool_calls_total[tool] += 1
            elif kind == "usage":
                phase = payload.get("phase") or "unknown"
                self.llm_tokens_total[(phase, "input")] += int(payload.get("input_tokens") or 0)
                self.llm_tokens_total[(phase, "output")] += int(payload.get("output_tokens") or 0)
            elif kind == "retask":
                self.investigation_retasks_total += 1
            elif kind == "fallback_verdict":
                self.investigation_fallback_verdicts_total += 1
            elif kind == "zero_tool_verdict_blocked":
                self.investigation_zero_tool_verdicts_total += 1
            elif kind == "error":
                self.investigation_errors_total += 1
            elif kind == "done":
                self.investigations_total += 1


_GLOBAL = _Metrics()


def get_metrics() -> _Metrics:
    """Module-level metrics accessor (overridable in tests if needed)."""
    return _GLOBAL


def _esc(label_value: str) -> str:
    """Escape a label value per Prometheus exposition rules."""
    return label_value.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def render(version: str) -> str:
    """Return the full Prometheus exposition text for the current state."""
    m = get_metrics()
    lines: list[str] = []

    lines.append("# HELP socai_build_info soc-ai build info; always 1.")
    lines.append("# TYPE socai_build_info gauge")
    lines.append(f'socai_build_info{{version="{_esc(version)}"}} 1')

    lines.append("# HELP socai_uptime_seconds Seconds since the soc-ai process booted.")
    lines.append("# TYPE socai_uptime_seconds gauge")
    lines.append(f"socai_uptime_seconds {int(time.time() - m.start_time)}")

    lines.append("# HELP socai_investigations_total Investigations fully streamed (any verdict).")
    lines.append("# TYPE socai_investigations_total counter")
    lines.append(f"socai_investigations_total {m.investigations_total}")

    lines.append(
        "# HELP socai_investigation_errors_total Investigations that yielded any error event."
    )
    lines.append("# TYPE socai_investigation_errors_total counter")
    lines.append(f"socai_investigation_errors_total {m.investigation_errors_total}")

    lines.append(
        "# HELP socai_investigation_retasks_total Investigations where the retask round fired."
    )
    lines.append("# TYPE socai_investigation_retasks_total counter")
    lines.append(f"socai_investigation_retasks_total {m.investigation_retasks_total}")

    lines.append(
        "# HELP socai_investigation_fallback_verdicts_total "
        "Investigations that emitted a synthesis-failure fallback (synthetic/M27) report."
    )
    lines.append("# TYPE socai_investigation_fallback_verdicts_total counter")
    lines.append(
        f"socai_investigation_fallback_verdicts_total {m.investigation_fallback_verdicts_total}"
    )

    lines.append(
        "# HELP socai_investigation_zero_tool_verdicts_total "
        "Zero-tool TP/FP verdicts blocked/coerced by the evidence gate."
    )
    lines.append("# TYPE socai_investigation_zero_tool_verdicts_total counter")
    lines.append(
        f"socai_investigation_zero_tool_verdicts_total {m.investigation_zero_tool_verdicts_total}"
    )

    lines.append("# HELP socai_tool_calls_total Per-tool call counts.")
    lines.append("# TYPE socai_tool_calls_total counter")
    for tool, count in sorted(m.tool_calls_total.items()):
        lines.append(f'socai_tool_calls_total{{tool="{_esc(tool)}"}} {count}')

    lines.append("# HELP socai_llm_tokens_total Cumulative LLM token usage by phase + direction.")
    lines.append("# TYPE socai_llm_tokens_total counter")
    for (phase, direction), count in sorted(m.llm_tokens_total.items()):
        lines.append(
            f'socai_llm_tokens_total{{phase="{_esc(phase)}",direction="{_esc(direction)}"}} {count}'
        )

    lines.append("")  # trailing newline
    return "\n".join(lines)
