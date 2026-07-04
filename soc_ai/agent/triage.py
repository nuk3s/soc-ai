"""Compatibility re-export of the triage report schema.

The models moved to the neutral :mod:`soc_ai.triage_models` (package root) so
consumers outside the agent package — notably the Oracle client — can import
the report types without executing ``soc_ai.agent.__init__`` (which imports
the orchestrator and used to create an oracle↔agent import cycle).

Import from :mod:`soc_ai.triage_models` in new code; this module remains the
stable historical import path.
"""

from __future__ import annotations

from soc_ai.triage_models import (
    InvestigationTranscript,
    RecommendedAction,
    RubricCoverage,
    TargetedGap,
    TriageReport,
    Verdict,
    WriteToolName,
)

__all__ = [
    "InvestigationTranscript",
    "RecommendedAction",
    "RubricCoverage",
    "TargetedGap",
    "TriageReport",
    "Verdict",
    "WriteToolName",
]
