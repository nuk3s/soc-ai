"""PydanticAI agent loop, prompts, model builders, reasoning-trace handling."""

from soc_ai.agent.orchestrator import (
    InvestigationContext,
    StepEvent,
    build_agent,
    build_investigator,
    build_investigator_model,
    build_model,
    build_synthesizer,
    build_synthesizer_model,
    investigate,
)
from soc_ai.agent.prompts import (
    INVESTIGATOR_PROMPT,
    SYNTHESIZER_PROMPT,
    SYSTEM_PROMPT,
    build_investigator_prompt,
    build_synthesizer_prompt,
)
from soc_ai.agent.reasoning import ReasoningMode, extract_reasoning_trace
from soc_ai.agent.triage import (
    InvestigationTranscript,
    RecommendedAction,
    TriageReport,
    Verdict,
    WriteToolName,
)

__all__ = [
    "INVESTIGATOR_PROMPT",
    "SYNTHESIZER_PROMPT",
    "SYSTEM_PROMPT",
    "InvestigationContext",
    "InvestigationTranscript",
    "ReasoningMode",
    "RecommendedAction",
    "StepEvent",
    "TriageReport",
    "Verdict",
    "WriteToolName",
    "build_agent",
    "build_investigator",
    "build_investigator_model",
    "build_investigator_prompt",
    "build_model",
    "build_synthesizer",
    "build_synthesizer_model",
    "build_synthesizer_prompt",
    "extract_reasoning_trace",
    "investigate",
]
