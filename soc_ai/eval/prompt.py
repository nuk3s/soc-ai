"""Build the oracle prompt for the eval harness.

The prompt has three pieces:

1. **System prompt** — a short, role-specific instruction that frames
   the oracle as a critic of a SOC triage agent's run. Cached.
2. **Architecture context block** — a brief description of the agent's
   single synth-first pipeline + the verbatim system prompts the agent
   itself runs against (``SYNTH_FIRST_SYSTEM_PROMPT`` for the verdict
   writer, ``INVESTIGATOR_PROMPT`` for the investigation loop,
   ``SYNTHESIZER_PROMPT`` for the loop-concluding synthesis). Cached.
   Lets the oracle critique prompt wording directly.
3. **User message** — the sanitized event trail, the final
   :class:`TriageReport`, and the three questions.

The system + architecture blocks get
``cache_control: {"type": "ephemeral"}`` so repeat runs share most
of the input cost.
"""

from __future__ import annotations

import json
from typing import Any

from soc_ai.agent.prompts import (
    INVESTIGATOR_PROMPT,
    SYNTH_FIRST_SYSTEM_PROMPT,
    SYNTHESIZER_PROMPT,
)

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

soc-ai triages every alert through ONE pipeline with staged escalation —
each stage handles what the previous could not:

1. **Prefetch + local enrichment** (deterministic, no LLM). The
   orchestrator pivots the alert across host / user / community-id and
   enriches IPs/domains/hashes (blocklists, MaxMind ASN/GeoIP,
   cloud-provider tags, optional MISP) into an enriched context.
2. **Decision template** (deterministic). Ordered pure-function
   templates may emit a *candidate verdict* — an anchor the synthesizer
   can keep, refine, or override.
3. **Definitely-investigate pre-check.** A malware/exploit rule signal,
   a concurrent host threat-context flag, or an external-reputation
   template match skips round 1 (`synth_round1_skipped`) and routes
   straight to the investigation loop.
4. **Synthesis round 1** (heavy model, NO tools) — the verdict writer.
   Reads the enriched context + materialized evidence + candidate and
   emits a `TriageReport` (`verdict`, `confidence`, `summary`,
   `citations`, `recommended_actions`); instead of guessing it may name
   ONE gap (`gap_for_investigator`: a specific tool + exact args).
5. **Phase D — targeted dispatch** (optional). The orchestrator runs
   exactly the tool call the synth named (a deterministic dispatcher —
   no LLM picks the tool), then synthesis round 2 finalizes over the
   combined evidence. At most one dispatch round by default.
6. **Investigation loop** (optional; supersedes Phase D when entered).
   A tool-equipped agent on the heavy model with the full read-tool
   surface (OQL/Zeek/case/detection queries, dataset discovery, raw
   event + payload decode, rule content, host/prevalence summaries,
   IP/domain/hash enrichment; per-call result clamps). Entered for
   definitely-investigate, when the round-1 verdict isn't
   evidence-backed (`investigate_when_unsure`), or for every alert when
   `fast_triage_enabled=false`. A synthesizer then concludes over the
   gathered transcript.
7. **Deterministic gates** (graders, not gatekeepers — they reshape the
   final report; they never re-run the model): citation validation +
   cap; the verdict floor (a TP/FP below `synthesis_confidence_floor`,
   default 0.6, that also lacks semantic citation coverage is rewritten
   to needs_more_info); targeted downgrades (e.g. solicited internal
   ICMP echo replies, ungrounded host-anchored TPs); the malware-label
   payload gate (a TP anchored only on a malware-named rule, without
   payload/tool corroboration, is downgraded); and the hard
   evidence gate (a TP/FP with zero tool evidence, no strong template,
   and no IOC/pivot hit is coerced to needs_more_info).
8. **Oracle** (opt-in second opinion). Uncertain / malware-non-TP /
   below-confidence verdicts may be adjudicated by a frontier model
   over a redacted payload; the local verdict is preserved alongside.

Event kinds in the JSONL trail: `session_start`,
`enriched_alert_context`, `decision_template_match`,
`synth_round1_skipped`, `investigation_loop_entered`, `tool_call`,
`tool_result`, `model_response` (with optional `reasoning_trace`),
`usage`, `investigation_transcript`, `retask`, `targeted_dispatch`,
`targeted_tool_result`, `self_consistency_vote`, `citation_validation`,
`citation_cap`, `verdict_floor_rewrite`, downgrade audits
(`icmp_solicited_downgrade`, `ungrounded_host_anchored_tp_downgrade`,
`malware_rule_name_ungrounded_downgrade`, `evidence_gate_downgrade`),
`oracle_escalation`, `oracle_adjudication`, `triage_report`,
`auto_ack`, `done`, `error`.

Note: `retask` is co-emitted alongside every `targeted_dispatch` for
metric continuity — `retask_count` counts Phase-D dispatches. There is
no separate low-confidence re-investigation round.

## Round-1 / round-2 synthesizer system prompt (verbatim)

```
{SYNTH_FIRST_SYSTEM_PROMPT}
```

## Investigation-loop investigator system prompt (verbatim)

```
{INVESTIGATOR_PROMPT}
```

## Loop-concluding synthesizer system prompt (verbatim)

```
{SYNTHESIZER_PROMPT}
```
"""


def architecture_block() -> str:
    """Return the architecture-context block (cached on the request).

    Includes the verbatim SYNTH_FIRST_SYSTEM_PROMPT (the verdict
    writer), INVESTIGATOR_PROMPT (the investigation loop) and
    SYNTHESIZER_PROMPT (the loop-concluding synthesis) so the oracle
    can critique their wording directly.
    """
    return _ARCH_SUMMARY.format(
        SYNTH_FIRST_SYSTEM_PROMPT=SYNTH_FIRST_SYSTEM_PROMPT,
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
   wording, tool surface, dispatch/loop-entry triggers, gate
   thresholds, model routing, output format, etc) would improve
   quality on this kind of alert? Be
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
