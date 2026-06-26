"""Build the oracle prompt for the eval harness.

The prompt has three pieces:

1. **System prompt** — a short, role-specific instruction that frames
   the oracle as a critic of a SOC triage agent's run. Cached.
2. **Architecture context block** — a brief description of the agent's
   two-stage flow + the verbatim ``INVESTIGATOR_PROMPT`` and
   ``SYNTHESIZER_PROMPT`` strings the agent itself runs against.
   Cached. Lets the oracle critique prompt wording directly.
3. **User message** — the sanitized event trail, the final
   :class:`TriageReport`, and the three questions.

The system + architecture blocks get
``cache_control: {"type": "ephemeral"}`` so repeat runs share most
of the input cost.
"""

from __future__ import annotations

import json
from typing import Any

from soc_ai.agent.prompts import INVESTIGATOR_PROMPT, SYNTHESIZER_PROMPT

SYSTEM_PROMPT = """\
You are evaluating a Security Onion triage agent's investigation.
Internal identifiers (private IPs, MAC addresses, internal hostnames,
usernames, internal emails) have been replaced with opaque labels
(IP_01, HOST_02, USER_03, MAC_04, EMAIL_05). Reason about labels as
stable references; don't try to guess what they map to. Public IPs,
public domains, file hashes, and CVE/ATT&CK identifiers are
preserved as-is — those are the IOCs the agent had to reason about.

Your role:
- Critique the agent's verdict based on the evidence it gathered.
- Suggest concrete architectural improvements (prompt edits, tool
  surface changes, flow tweaks).
- Be honest. An "uncertain" or "I disagree" answer is more useful
  than a confident wrong one.

The agent runs on locally-hosted Nemotron 3 models via LiteLLM and
reads from a Security Onion Elasticsearch cluster. Output as
Markdown with three sections matching the user's questions.
"""

_ARCH_SUMMARY = """\
# soc-ai architecture (what the agent looks like under the hood)

soc-ai is a two-stage Security Onion triage agent:

- **Investigator** (fast 30B model, e.g. Nemotron 3 Nano). Reads the
  pre-fetched alert context, then uses a fixed read-tool surface to
  gather evidence. Tools available: `t_query_events_oql`,
  `t_query_zeek_logs`, `t_query_cases`, `t_query_detections`,
  `t_get_playbooks`, `t_enrich_ip`, `t_enrich_domain`, `t_enrich_hash`,
  `t_lookup_runbook`. Tool returns clamp at ~12KB per call;
  `max_results` ceilings cap each tool's payload size to defend the
  64K context window. Emits an `InvestigationTranscript`
  (`evidence`, `tentative_summary`, `open_questions`).
- **Synthesizer** (heavy 120B model, e.g. Nemotron 3 Super). No
  tools. Reads the transcript and emits a `TriageReport`
  (`verdict`, `confidence`, `summary`, `citations`,
  `recommended_actions`).
- **Retask** (conditional). If `synthesis_confidence_floor` (default
  0.6) isn't met, the investigator runs ONE more round on the
  HEAVY model with the round-1 transcript + open questions; the
  synthesizer then synthesizes over the combined evidence. Round-2
  is bounded tighter (15 tool calls vs 100) so it can't blow context.

The orchestrator emits SSE events at every step (the JSONL trail
included below): `session_start`, `alert_context`, `tool_call`,
`tool_result`, `model_response` (with optional `reasoning_trace`),
`investigation_transcript`, `usage`, `retask`, `triage_report`,
`approval_required`, `done`, `error`.

## Investigator system prompt (verbatim)

```
{INVESTIGATOR_PROMPT}
```

## Synthesizer system prompt (verbatim)

```
{SYNTHESIZER_PROMPT}
```
"""


def architecture_block() -> str:
    """Return the architecture-context block (cached on the request).

    Includes the verbatim INVESTIGATOR_PROMPT + SYNTHESIZER_PROMPT so
    the oracle can critique their wording directly.
    """
    return _ARCH_SUMMARY.format(
        INVESTIGATOR_PROMPT=INVESTIGATOR_PROMPT,
        SYNTHESIZER_PROMPT=SYNTHESIZER_PROMPT,
    )


def build_user_message(
    *,
    alert_id_label: str,
    sanitized_events: list[dict[str, Any]],
    sanitized_report: dict[str, Any] | None,
    expected_verdict: str | None = None,
) -> str:
    """Build the user-message body the oracle receives.

    Args:
        alert_id_label: the alert id (already sanitized — pass the
            label from the mapping, not the raw ES `_id`, since
            internal alert ids may include hostnames in some
            deployments).
        sanitized_events: every SSE event payload, post-sanitization,
            in chronological order.
        sanitized_report: the final ``TriageReport`` payload (also
            post-sanitization). May be ``None`` if the run errored
            before synthesis — the prompt notes that explicitly.
        expected_verdict: for synthetic scenarios only — the planted,
            known-correct verdict. When set, a ground-truth block is
            appended so the oracle grades factually rather than
            subjectively. None for real-alert grading.
    """
    events_jsonl = "\n".join(json.dumps(e, default=str) for e in sanitized_events)

    if sanitized_report is None:
        report_block = (
            "*(no triage_report — the run errored before synthesis. "
            "Critique what the agent attempted; Q1 should compare what "
            "evidence it had against what it should have done next.)*"
        )
    else:
        report_block = (
            f"- **verdict**: `{sanitized_report.get('verdict')}`\n"
            f"- **confidence**: `{sanitized_report.get('confidence')}`\n"
            f"- **summary**: {sanitized_report.get('summary') or '(empty)'}\n"
            f"- **citations**: {sanitized_report.get('citations') or '(none)'}\n"
            f"- **recommended_actions**:\n```json\n"
            f"{json.dumps(sanitized_report.get('recommended_actions') or [], indent=2)}\n```"
        )

    ground_truth_block = ""
    if expected_verdict is not None:
        ground_truth_block = (
            f"\n## Ground truth (synthetic scenario)\n"
            f"This alert is a synthetic evaluation scenario. "
            f"The planted, known-correct verdict is: `{expected_verdict}`.\n"
            f"Grade the agent's conclusion against this ground truth, "
            f"not against your own judgment.\n"
        )

    return f"""\
# What soc-ai did

{architecture_block()}

## Run trail (sanitized SSE events, JSONL, chronological)

```jsonl
{events_jsonl}
```

## Final report (sanitized)

Alert id: `{alert_id_label}`

{report_block}
{ground_truth_block}
# Three questions

Please answer all three:

1. **Is this conclusion correct?** Given the evidence in the run
   trail above, do you agree with the verdict + confidence? (yes /
   no / partially / unable to tell)
2. **Why?** If you agree, what evidence most strongly supports the
   verdict? If you disagree, what did the agent miss or
   misinterpret? Cite specific events from the trail (e.g. "the
   `t_enrich_ip` result at sequence 7 returned …").
3. **Architecture changes for better future results?** Given the
   prompts + flow shown above, what concrete changes (prompt
   wording, tool surface, retask trigger, model routing, output
   format, etc) would improve quality on this kind of alert? Be
   specific. Prioritize by expected impact (high / medium / low)
   and call out which change is highest-leverage.

Format your response as Markdown with three top-level sections
(`## 1. Verdict`, `## 2. Why`, `## 3. Architecture`). Be honest —
"uncertain" or "I disagree" is more useful than a confident wrong
answer.

The FIRST line of your verdict section must be exactly:
AGREEMENT: <yes|no|partial>
followed by your reasoning.
"""
