"""Admin-editable Settings overlay (the hot-apply core).

A small, explicit whitelist of :class:`~soc_ai.config.Settings` attributes may
be overridden at runtime by an admin via the config console. Overrides are
JSON-encoded scalars persisted in the ``config_overrides`` table; they are
re-applied to ``app.state.settings`` at startup so they survive restarts, and
hot-applied via ``setattr`` immediately on save when the field is marked hot.

SECURITY: the whitelist includes the Danger Zone connection settings (hosts,
usernames) and write-only secret specs (``secret=True``: passwords, api-keys,
tokens). A secret override is persisted as Fernet ciphertext keyed by
``CONFIG_SECRET_KEY`` (see :mod:`soc_ai.store.secret_box`) and is write-only:
it is never rendered back or echoed in a response body. Connection identity is
stored in plaintext. The ``config_overrides`` table is therefore sensitive in
dumps, backups and exports, even though a dump alone yields no live secret
without the key.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any, Literal
from urllib.parse import urlparse

from pydantic import ValidationError as PydanticValidationError
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from soc_ai.config import SO_LOGIN_FLOWS, Settings
from soc_ai.store.models import ConfigOverride
from soc_ai.store.secret_box import SecretBox

_LOGGER = logging.getLogger(__name__)

SettingType = Literal["bool", "str", "float", "int", "csv", "select"]


@dataclass(frozen=True)
class SettingSpec:
    """Metadata for one admin-editable setting."""

    key: str  # the override key (== the Settings attribute name)
    attr: str  # the Settings attribute name to setattr
    type: SettingType
    label: str
    section: str
    hot: bool  # True = applied live by setattr; False = needs restart
    help: str = ""  # one-line description shown under the control
    # Inclusive numeric bounds for int/float settings (None = unbounded). Out-of-
    # range values are rejected with ValueError so a typo can't, e.g., set a
    # temperature of 50 or a negative request limit.
    min_value: float | None = None
    max_value: float | None = None
    # Danger Zone: a connection/secret setting gated behind a typed confirm.
    # Always hot=False (it affects clients built at startup → restart-required).
    danger: bool = False
    # Secret value: persisted Fernet-encrypted, never rendered back, write-only
    # (an empty submission leaves it unchanged). Requires a config_secret_key.
    secret: bool = False
    day1: bool = False
    """Day-1 tier: shown by default in the Config console. Everything else sits
    behind a per-section Advanced fold. Default False so a NEW setting is
    hidden-by-default — the day-1 wall cannot regrow by accident. Hard bound
    (<=10) and the exact curated set are pinned by tests/test_config_day1_tier.py."""
    # Fixed-choice string setting (type="select"): the exact allowed values, in
    # display order. Membership is enforced in coerce()/_validate_typed(), so a
    # typo'd override fails the SAVE instead of crashing agent construction on
    # the next investigation (Settings.validate_assignment would reject it at
    # apply time — after it was already persisted).
    options: tuple[str, ...] | None = None


# The whitelist of admin-editable settings. Order is display order within a
# section. Every field listed here MUST exist on Settings and MUST NOT be a
# secret. All inc1 keys are hot (applied live on save).
WHITELIST: tuple[SettingSpec, ...] = (
    SettingSpec(
        key="oracle_enabled",
        attr="oracle_enabled",
        type="bool",
        label="Oracle enabled",
        section="Oracle",
        hot=True,
        help=(
            "The Oracle is a cloud frontier model that reviews a local verdict. "
            "The settings below select which verdicts it reviews."
        ),
    ),
    SettingSpec(
        key="oracle_model",
        attr="oracle_model",
        type="str",
        label="Oracle model alias",
        section="Oracle",
        hot=True,
    ),
    SettingSpec(
        key="oracle_escalate_needs_more_info",
        attr="oracle_escalate_needs_more_info",
        type="bool",
        label="Escalate if the local verdict is needs_more_info",
        section="Oracle",
        hot=True,
    ),
    SettingSpec(
        key="oracle_escalate_malware_non_tp",
        attr="oracle_escalate_malware_non_tp",
        type="bool",
        label="Escalate a malware or exploit alert without a high-confidence verdict",
        section="Oracle",
        hot=True,
    ),
    SettingSpec(
        key="oracle_escalate_below_confidence",
        attr="oracle_escalate_below_confidence",
        type="float",
        label="Escalate if the local confidence is below",
        section="Oracle",
        hot=True,
        help=(
            "This setting is the confidence floor for a local verdict. "
            "A higher floor sends more verdicts to the Oracle. "
            "The range is 0.0 to 1.0."
        ),
        min_value=0.0,
        max_value=1.0,
    ),
    SettingSpec(
        key="oracle_skip_after_confident_loop",
        attr="oracle_skip_after_confident_loop",
        type="float",
        label="Trust a confident loop verdict at or above",
        section="Oracle",
        hot=True,
        help=(
            "This setting is the confidence floor for a verdict from the "
            "investigation loop. A malware or attack verdict at or above the floor "
            "stays local. The Oracle does not review it. The range is 0.0 to 1.0."
        ),
        min_value=0.0,
        max_value=1.0,
    ),
    SettingSpec(
        key="fast_triage_enabled",
        attr="fast_triage_enabled",
        type="bool",
        label="Fast verdict",
        section="Agent",
        hot=True,
        help=(
            "This setting lets the agent skip tools if the first pass is "
            "confident. The verdict arrives faster and the results are shallower. "
            "Turn it off to always run the full tool-driven loop."
        ),
    ),
    SettingSpec(
        key="investigate_when_unsure",
        attr="investigate_when_unsure",
        type="bool",
        label="Investigate if the round-1 verdict has no evidence",
        section="Agent",
        hot=True,
        help="soc-ai runs the full tool-driven loop for that alert.",
    ),
    SettingSpec(
        key="investigator_emits_report",
        attr="investigator_emits_report",
        type="bool",
        label="The investigator writes the report",
        section="Agent",
        hot=True,
        help=(
            "The investigator writes the report itself. The second synthesis call "
            "does not run. The verdict arrives sooner and it keeps the citations "
            "the loop gathered."
        ),
    ),
    SettingSpec(
        key="synth_round1_always",
        attr="synth_round1_always",
        type="bool",
        label="Always run the first-pass synthesis",
        section="Agent",
        hot=True,
        help=(
            "soc-ai runs the first-pass verdict even when that pass cannot close "
            "the alert. By default it runs the pass only when the pass can close "
            "the alert. The investigation loop replaces the first-pass verdict on "
            "every other alert, so the pass costs time and tokens for nothing. "
            "Turn this on to get the first-pass verdict back in the timeline."
        ),
    ),
    SettingSpec(
        key="webui_extra_detections",
        attr="webui_extra_detections",
        type="bool",
        label="Show non-Suricata SO detections in the feed",
        section="Queries",
        hot=True,
        help=(
            "The alerts feed also shows Sigma hits and Zeek ATTACK notices. "
            "Each one carries a tag for its type."
        ),
    ),
    SettingSpec(
        key="analyst_model",
        attr="analyst_model",
        type="str",
        label="Analyst model",
        section="Agent",
        hot=True,
        day1=True,
        help=(
            "The analyst agent uses this LiteLLM model for every investigation. "
            "A bad value fails every investigation."
        ),
    ),
    SettingSpec(
        key="analyst_cloud_redaction",
        attr="analyst_cloud_redaction",
        type="bool",
        label="Redact internal identifiers before a cloud analyst model",
        section="Agent",
        hot=True,
        help=(
            "soc-ai replaces internal IP addresses, hostnames and usernames with "
            "opaque labels. The labels cover the context, the prompts and the tool "
            "results. soc-ai restores the real values in the model output. The "
            "model reasons over labels, so verdict quality drops. Leave this off "
            "for a local model."
        ),
    ),
    SettingSpec(
        key="analyst_redaction_fail_closed",
        attr="analyst_redaction_fail_closed",
        type="bool",
        label="Fail closed on a residual identifier in analyst egress",
        section="Agent",
        hot=True,
        help=(
            "This setting applies only if the redaction above is on. If it is on, "
            "soc-ai blocks an outbound payload that still holds an internal "
            "identifier. soc-ai does not call the model. The run lands a pipeline "
            "error that names the leaked count. If it is off, a sanitize miss "
            "still leaves the network."
        ),
    ),
    SettingSpec(
        key="host_risk_window_hours",
        attr="host_risk_window_hours",
        type="int",
        label="Host-risk window each side (hours)",
        section="Agent",
        hot=True,
        help=(
            "This setting sets the window for the host-risk profile. The profile "
            "is the endpoint's recent alert histogram. A wider window reads more "
            "alerts. 0 turns the profile off."
        ),
        min_value=0,
        max_value=168,
    ),
    SettingSpec(
        key="agent_tool_calls_limit",
        attr="agent_tool_calls_limit",
        type="int",
        label="Maximum tool calls per investigation",
        section="Agent",
        hot=True,
        help=("This setting caps the tool calls in one investigation. The loop stops at the cap."),
        min_value=1,
        max_value=200,
    ),
    SettingSpec(
        key="agent_request_limit",
        attr="agent_request_limit",
        type="int",
        label="Maximum model requests per investigation",
        section="Agent",
        hot=True,
        help="This setting caps the model requests in one investigation.",
        min_value=1,
        max_value=100,
    ),
    SettingSpec(
        key="investigator_retries",
        attr="investigator_retries",
        type="int",
        label="Investigation-loop schema retries",
        section="Agent",
        hot=True,
        help=(
            "This setting caps the Pydantic-AI output-schema retries for the investigation loop."
        ),
        min_value=1,
        max_value=20,
    ),
    SettingSpec(
        key="phase_d_max_rounds",
        attr="phase_d_max_rounds",
        type="int",
        label="Maximum targeted-dispatch rounds",
        section="Agent",
        hot=True,
        help=(
            "This setting caps the gap, tool and re-synthesis rounds the "
            "synthesizer runs in one investigation."
        ),
        min_value=1,
        max_value=3,
    ),
    SettingSpec(
        key="synthesizer_temperature",
        attr="synthesizer_temperature",
        type="float",
        label="Synthesizer temperature",
        section="Agent",
        hot=True,
        help=(
            "This setting sets the synthesizer temperature. A lower value makes a "
            "verdict more deterministic. The tuned default is 0.2."
        ),
        min_value=0.0,
        max_value=2.0,
    ),
    SettingSpec(
        key="chat_regrounding_attempts",
        attr="chat_regrounding_attempts",
        type="int",
        label="Chat re-grounding attempts",
        section="Agent",
        hot=True,
        help=(
            "This setting sets how many times soc-ai re-runs a chat turn. The "
            "re-run cites an unsupported claim with a tool or removes it. 0 "
            "redacts whatever stays ungrounded."
        ),
        min_value=0,
        max_value=3,
    ),
    SettingSpec(
        key="general_chat_enabled",
        attr="general_chat_enabled",
        type="bool",
        label="Dashboard chat",
        section="Agent",
        hot=True,
        help=(
            "The Dashboard answers a question in one turn. It proposes a hunt if "
            "the question needs a sweep. The default is on. Nothing runs until an "
            "analyst asks. Turn it off to reclaim model capacity and to remove the "
            "box from the screen. This setting applies live."
        ),
    ),
    SettingSpec(
        key="synthesizer_output_mode",
        attr="synthesizer_output_mode",
        type="select",
        label="Synthesizer structured-output mode",
        section="Agent",
        hot=True,
        help=(
            "This setting sets how the no-tools synthesizers obtain the "
            "TriageReport. native uses server-side guided decoding. Guided decoding "
            "is the strongest fix for schema wobble on a weaker model. prompted "
            "returns JSON inside the text. Validate a candidate with "
            "`soc-ai model-probe --output-mode` first."
        ),
        options=("tool", "native", "prompted"),
    ),
    SettingSpec(
        key="analyst_tool_choice_required",
        attr="analyst_tool_choice_required",
        type="bool",
        label="Force tool_choice=required",
        section="Agent",
        hot=True,
        help=(
            "This setting allows tool_choice='required' for structured output. "
            "The default forces tool_choice='auto' as a vLLM parser workaround. "
            "The result changes per backend. Measure it with "
            "`soc-ai model-probe --tool-choice required` first."
        ),
    ),
    SettingSpec(
        key="investigator_temperature",
        attr="investigator_temperature",
        type="float",
        label="Investigator temperature",
        section="Agent",
        hot=True,
        help=(
            "This setting sets the investigator temperature. A higher value makes "
            "the tool use more exploratory. The tuned default is 0.4."
        ),
        min_value=0.0,
        max_value=2.0,
    ),
    SettingSpec(
        key="verdict_consistency_samples",
        attr="verdict_consistency_samples",
        type="int",
        label="Verdict self-consistency samples",
        section="Agent",
        hot=True,
        help=(
            "This setting sets how many times soc-ai runs the final verdict "
            "synthesis. soc-ai takes the majority verdict. A split lands "
            "`inconclusive`. 1 is the default and turns the vote off. Each extra "
            "sample is one more synthesizer call."
        ),
        min_value=1,
        max_value=5,
    ),
    SettingSpec(
        key="auto_triage_max_targets",
        attr="auto_triage_max_targets",
        type="int",
        label="Maximum alerts per Investigate sweep",
        section="Triage automation",
        hot=True,
        day1=True,
        help=("This setting caps the alerts that one Bulk or Auto-Investigate run investigates."),
        min_value=1,
        max_value=500,
    ),
    SettingSpec(
        key="litellm_max_retries",
        attr="litellm_max_retries",
        type="int",
        label="LLM gateway retry attempts",
        section="Agent",
        hot=True,
        help=(
            "This setting sets the retries after a transient gateway error. "
            "A higher value survives a longer proxy outage."
        ),
        min_value=0,
        max_value=10,
    ),
    SettingSpec(
        key="synthesizer_max_response_tokens",
        attr="synthesizer_max_response_tokens",
        type="int",
        label="Synthesizer response cap (tokens)",
        section="Agent",
        hot=True,
        help=(
            "This setting caps the synthesizer reasoning and report per call. "
            "soc-ai sends it as max_completion_tokens. A reasoning model can spend "
            "the whole budget and truncate before it states a verdict. The run then "
            "falls back to needs-more-info. Raise the cap for a verbose reasoning "
            "model."
        ),
        min_value=1000,
        max_value=200_000,
    ),
    SettingSpec(
        key="model_context_window_tokens",
        attr="model_context_window_tokens",
        type="int",
        label="Model context window (tokens)",
        section="Agent",
        hot=True,
        help=(
            "This setting is the input window soc-ai budgets context against. 0 "
            "reads the window from the LiteLLM gateway /model/info. 0 is the "
            "recommended value. If the window is known, soc-ai trims an oversized "
            "alert context before the first model call. It drops the oldest pivot "
            "events first."
        ),
        min_value=0,
        max_value=10_000_000,
    ),
    SettingSpec(
        key="auto_ack_fp_enabled",
        attr="auto_ack_fp_enabled",
        type="bool",
        label="Auto-acknowledge high-confidence false positives",
        section="Triage automation",
        hot=True,
        help=(
            "soc-ai acknowledges a completed investigation in Security Onion if "
            "its verdict is false_positive at or above the threshold below. An "
            "auto-triage sweep also acknowledges an alert that inherits such a "
            "verdict inside the inherit window. The alert must share the rule, the "
            "source and the destination. The default is on, and soc-ai audits every "
            "unattended acknowledgement. soc-ai never acknowledges a high or "
            "critical severity alert, and never a malware or exploit alert. To "
            "clear a standing false-positive backlog, run an auto-triage sweep over "
            "those alerts and lower the severity floor to medium or low. Turn this "
            "setting off to require a click for every acknowledgement."
        ),
    ),
    SettingSpec(
        key="auto_ack_fp_threshold",
        attr="auto_ack_fp_threshold",
        type="float",
        label="Auto-acknowledge confidence threshold for a false positive",
        section="Triage automation",
        hot=True,
        help=(
            "This setting is the minimum confidence for an automatic "
            "acknowledgement. The recommended value is 0.7. "
            "The range is 0.0 to 1.0."
        ),
        min_value=0.0,
        max_value=1.0,
    ),
    SettingSpec(
        key="auto_triage_min_severity",
        attr="auto_triage_min_severity",
        type="str",
        label="Auto-Investigate minimum severity",
        section="Triage automation",
        hot=True,
        day1=True,
        help=(
            "A sweep triages this severity and above. The values are critical, "
            "high, medium and low. The default is high, so a sweep triages critical "
            "and high detections. Set it to medium to add the medium-severity "
            "detections. A sweep also covers an alert whose document carries no "
            "severity, because a floor needs a value to compare. Turn on the "
            "schedule below to run sweeps automatically."
        ),
    ),
    SettingSpec(
        key="auto_triage_inheritance_enabled",
        attr="auto_triage_inheritance_enabled",
        type="bool",
        label="Inherit verdicts for similar alerts",
        section="Triage automation",
        hot=True,
        help=(
            "Auto-Investigate skips an alert if soc-ai already triaged a similar "
            "alert in the inherit window. A similar alert shares the rule, the "
            "source and the destination. The new alert inherits that verdict. Turn "
            "this setting off to investigate every alert on its own. This setting "
            "applies live."
        ),
    ),
    SettingSpec(
        key="auto_triage_schedule_enabled",
        attr="auto_triage_schedule_enabled",
        type="bool",
        label="Continuous auto-investigate",
        section="Triage automation",
        hot=True,
        day1=True,
        help=(
            "soc-ai runs Auto-Investigate on a schedule and drains the untriaged "
            "backlog. Each sweep covers every detection at or above the minimum "
            "severity above. The default is off, because the schedule makes "
            "continuous model calls. This setting applies live."
        ),
    ),
    SettingSpec(
        key="auto_triage_schedule_interval_minutes",
        attr="auto_triage_schedule_interval_minutes",
        type="int",
        label="Continuous auto-investigate interval (minutes)",
        section="Triage automation",
        hot=True,
        day1=True,
        help=(
            "This setting is the minimum number of minutes between scheduled "
            "sweeps. A lower value drains the backlog faster. A lower value also "
            "makes more model calls."
        ),
        min_value=1,
        max_value=1440,
    ),
    SettingSpec(
        key="hunt_schedules_enabled",
        attr="hunt_schedules_enabled",
        type="bool",
        label="Scheduled hunts",
        section="Triage automation",
        hot=True,
        help=(
            "soc-ai runs a saved hunt automatically on its own interval. Set that "
            "interval in the Hunt Console. This setting is the master switch, so "
            "off stops every scheduled hunt. The default is off, because a schedule "
            "makes recurring model calls. This setting applies live."
        ),
    ),
    SettingSpec(
        key="hunt_spec_sweeps_enabled",
        attr="hunt_spec_sweeps_enabled",
        type="bool",
        label="Catalog sweeps",
        section="Triage automation",
        hot=True,
        help=(
            "soc-ai runs the declarative hunt catalog on an interval. It records a "
            "finding for anything new. A sweep makes no model call. It runs two "
            "Elasticsearch queries per spec, so the cost is query load. The default "
            "is off, because a sweep writes findings unattended. Run "
            "`soc-ai spec-sweep --shadow` for a week first and read the counts."
        ),
    ),
    SettingSpec(
        key="hunt_spec_sweep_interval_minutes",
        attr="hunt_spec_sweep_interval_minutes",
        type="int",
        label="Minutes between catalog sweeps",
        section="Triage automation",
        hot=True,
        help=(
            "This setting is the number of minutes between catalog sweeps. The "
            "floor is 5 minutes, because a sweep runs no model. Keep the look-back "
            "window wider than this interval. A wider window still sees a condition "
            "that arrived during an outage."
        ),
        min_value=5,
        max_value=1440,
    ),
    SettingSpec(
        key="hunt_spec_sweep_window_minutes",
        attr="hunt_spec_sweep_window_minutes",
        type="int",
        label="Catalog sweep look-back window (minutes)",
        section="Triage automation",
        hot=True,
        help=(
            "This setting is how far back each sweep looks. Keep it wider than the "
            "interval. A window as short as the interval misses anything that "
            "arrived during a restart or an ingest lag. The fire-once gate stops "
            "the overlap from making repeat findings."
        ),
        min_value=5,
        max_value=43200,
    ),
    SettingSpec(
        key="catalog_hunt_rows",
        attr="catalog_hunt_rows",
        type="bool",
        label="Record a hunt row for each analytic hit",
        section="Hunting",
        hot=True,
        help=(
            "The catalog sweep writes a hunt row for each hit, as it did before "
            "1.5.0. Off, it writes the observation only."
        ),
    ),
    SettingSpec(
        key="hunting_prior_sweep_enabled",
        attr="hunting_prior_sweep_enabled",
        type="bool",
        label="Run the profile sweep",
        section="Hunting",
        hot=True,
        help=(
            "soc-ai compares each host with its own baseline every hour and "
            "records what departs. In shadow the sweep writes observations and "
            "raises nothing."
        ),
    ),
    SettingSpec(
        key="hunting_prior_sweep_interval_minutes",
        attr="hunting_prior_sweep_interval_minutes",
        type="int",
        label="Minutes between profile sweeps",
        section="Hunting",
        hot=True,
        help=(
            "This setting is the number of minutes between profile sweeps. The "
            "floor is 15 minutes. A sweep makes no model call. It makes several "
            "Elasticsearch queries per dimension, so the cost is query load."
        ),
        min_value=15,
        max_value=1440,
    ),
    SettingSpec(
        key="lead_auto_hunt",
        attr="lead_auto_hunt",
        type="bool",
        label="A lead starts its own hunt",
        section="Hunting",
        hot=True,
        help=(
            "A lead that has never had a hunt starts one when it forms. Off, a "
            "lead waits for an analyst to start the hunt. soc-ai leaves four "
            "leads to the analyst: a dismissed lead, a reopened lead, a shadow "
            "lead, and a lead that cites no document. Use Hunt on the lead to "
            "start those. This setting applies live."
        ),
    ),
    SettingSpec(
        key="lead_auto_hunt_concurrency",
        attr="lead_auto_hunt_concurrency",
        type="int",
        label="Lead hunts at once",
        section="Hunting",
        hot=True,
        help=(
            "This setting is how many lead hunts soc-ai runs at the same time. "
            "It counts the hunts the loop started. A hunt an analyst started by "
            "hand does not count. To stop every lead hunt, turn the setting "
            "above off."
        ),
        min_value=1,
        max_value=10,
    ),
    SettingSpec(
        key="sigma_authoring_enabled",
        attr="sigma_authoring_enabled",
        type="bool",
        label="Draft detections from hunt findings",
        section="Triage automation",
        hot=True,
        help=(
            "soc-ai drafts a Sigma rule from a confirmed true-positive hunt "
            "finding. It validates the schema and runs a dry run over the grid. It "
            "then exports the rule for the analyst to paste into the Security Onion "
            "Detections module. soc-ai never writes the rule to Security Onion. The "
            "default is off. This setting applies live."
        ),
    ),
    SettingSpec(
        key="analytic_drafting_enabled",
        attr="analytic_drafting_enabled",
        type="bool",
        label="Draft analytics from findings",
        section="Triage automation",
        hot=True,
        help=(
            "soc-ai drafts a catalog analytic from a threat hunt finding. It "
            "validates the analytic and runs a dry run over the last 30 days. It "
            "stores the analytic in the local tier as a candidate. A candidate "
            "does not run until an analyst moves it to shadow. This setting "
            "applies live."
        ),
    ),
    SettingSpec(
        key="audit_verify_schedule_enabled",
        attr="audit_verify_schedule_enabled",
        type="bool",
        label="Verify the audit trail on a schedule",
        section="Audit trail",
        hot=True,
        help=(
            "soc-ai re-checks the tamper-evident hash chain on the interval below. "
            "It raises an alarm if the chain does not verify. The default is on. "
            "Each run costs one bounded Elasticsearch read."
        ),
    ),
    SettingSpec(
        key="audit_verify_schedule_interval_hours",
        attr="audit_verify_schedule_interval_hours",
        type="int",
        label="Hours between audit-trail checks",
        section="Audit trail",
        hot=True,
        help=(
            "This setting is the number of hours between audit-trail checks. The "
            "default is 24 hours. A break in the chain is a standing condition."
        ),
        min_value=1,
        max_value=720,
    ),
    SettingSpec(
        key="audit_verify_days",
        attr="audit_verify_days",
        type="int",
        label="Days of trail each check reads",
        section="Audit trail",
        hot=True,
        help=(
            "This setting is how far back the scheduled check reads. A wider window "
            "makes a stronger claim and a heavier read. Run `soc-ai audit verify` "
            "for a full-index scan on demand."
        ),
        min_value=1,
        max_value=3650,
    ),
    SettingSpec(
        key="synthesis_confidence_floor",
        attr="synthesis_confidence_floor",
        type="float",
        label="Synthesis confidence floor",
        section="Agent",
        hot=True,
        help=(
            "This setting is the confidence floor for a true-positive or "
            "false-positive verdict. soc-ai rewrites a verdict below the floor to "
            "needs_more_info if it also lacks semantic citation coverage. The tuned "
            "default is 0.6."
        ),
        min_value=0.0,
        max_value=1.0,
    ),
    SettingSpec(
        key="investigator_max_response_tokens",
        attr="investigator_max_response_tokens",
        type="int",
        label="Investigator maximum response tokens per turn",
        section="Agent",
        hot=True,
        help=(
            "This setting caps the reasoning and the content in one investigator "
            "turn. A long turn cannot then dominate the run time. The calibrated "
            "default is 32000."
        ),
        min_value=2000,
        max_value=128000,
    ),
    # ---- QUERIES: index patterns + the web-UI alerts feed query (hot) --------
    # All hot=True: these are read fresh from settings per query/request (the
    # OQL/ES query builders and the alerts feed re-read them every call), so a
    # change applies live to the next query.
    SettingSpec(
        key="events_index_pattern",
        attr="events_index_pattern",
        type="str",
        label="Events index pattern",
        section="Queries",
        hot=True,
        day1=True,
        help=(
            "This setting is the wildcard Elasticsearch index or alias pattern for "
            "Security Onion events. Two examples are *:so-* and logs-*. Every alert "
            "query and every event query uses it."
        ),
    ),
    SettingSpec(
        key="cases_index_pattern",
        attr="cases_index_pattern",
        type="str",
        label="Cases index pattern",
        section="Queries",
        hot=True,
        help=(
            "This setting is the wildcard Elasticsearch index or alias pattern for "
            "Security Onion cases. One example is *:so-case-*."
        ),
    ),
    SettingSpec(
        key="detections_index_pattern",
        attr="detections_index_pattern",
        type="str",
        label="Detections index pattern",
        section="Queries",
        hot=True,
        help=(
            "This setting is the wildcard Elasticsearch index or alias pattern for "
            "Security Onion detections. One example is *:so-detection-*."
        ),
    ),
    SettingSpec(
        key="playbooks_index_pattern",
        attr="playbooks_index_pattern",
        type="str",
        label="Playbooks index pattern",
        section="Queries",
        hot=True,
        help=(
            "This setting is the wildcard Elasticsearch index or alias pattern for "
            "Security Onion playbooks. One example is *:so-playbook-*."
        ),
    ),
    SettingSpec(
        key="webui_alerts_query",
        attr="webui_alerts_query",
        type="str",
        label="Web-UI alerts feed query (OQL)",
        section="Queries",
        hot=True,
        day1=True,
        help=(
            "This setting is the OQL filter that selects the events in the alerts "
            "feed. The default is tags:alert OR event.kind:alert. tags:alert is the "
            "Security Onion tag. event.kind:alert is the ECS field an Elastic "
            "Defend endpoint alert carries. soc-ai reads this setting on every feed "
            "fetch. `soc-ai doctor` counts it against the alternatives on your grid."
        ),
    ),
    SettingSpec(
        key="webui_inherit_window_days",
        attr="webui_inherit_window_days",
        type="int",
        label="Verdict inheritance window (days)",
        section="Queries",
        hot=True,
        help=(
            "This setting is how far back the feed looks for a prior verdict. A "
            "new alert inherits that verdict if the rule, the source and the "
            "destination match."
        ),
        min_value=0,
        max_value=365,
    ),
    SettingSpec(
        key="es_fail_on_partial_results",
        attr="es_fail_on_partial_results",
        type="bool",
        label="Fail queries that only read part of the grid",
        section="Queries",
        hot=True,  # read per search off the live Settings the ES client holds
        help=(
            "On is the default. A search with a failed or timed-out shard then "
            "raises 'grid unavailable' and returns no partial hits. An outage "
            "cannot read as a quiet network. Turn this off only if you run with a "
            "red shard and want partial data. soc-ai logs the failures either way. "
            "The health probe, the degraded banner and the bell always report a "
            "partial read."
        ),
    ),
    SettingSpec(
        key="pcap_enabled",
        attr="pcap_enabled",
        type="bool",
        label="PCAP retrieval enabled",
        section="PCAP",
        hot=True,
        help="soc-ai fetches the PCAP over SSH with suripcap.",
    ),
    SettingSpec(
        key="web_search_enabled",
        attr="web_search_enabled",
        type="bool",
        label="Web search enabled",
        section="Web research",
        hot=True,
        help="soc-ai searches through the SearXNG instance set below.",
    ),
    SettingSpec(
        key="allow_online_enrichment",
        attr="allow_online_enrichment",
        type="bool",
        label="Online enrichment enabled",
        section="Online enrichment",
        hot=True,
        help=(
            "The default is off, because the rest of soc-ai reads local feeds "
            "only. On lets the agent reach a third-party reputation or asset API "
            "over the internet. GreyNoise and Shodan are two such providers. Set "
            "the provider keys in the API keys panel below. Shodan InternetDB "
            "needs no key."
        ),
    ),
    SettingSpec(
        key="update_check_enabled",
        attr="update_check_enabled",
        type="bool",
        label="Check GitHub for updates",
        section="Updates",
        hot=True,
        help=(
            "The default is off, so soc-ai makes no outbound call to check for an "
            "update. On, the 'Check for updates' button on the About page compares "
            "the running version against the latest GitHub release. The check is "
            "manual and soc-ai never polls. soc-ai sends nothing about your "
            "environment or your alerts. soc-ai compares the version locally."
        ),
    ),
    SettingSpec(
        key="misp_url",
        attr="misp_url",
        type="str",
        label="MISP base URL",
        section="Online enrichment",
        # Unlike the rest of this hot group: MISP_URL feeds the MispClient built
        # once at startup (soc_ai.tools.enrichment.MispClient, held on
        # app.state.misp) rather than re-read per call, so a change needs a
        # restart to take effect — same reasoning as so_host/es_hosts/
        # litellm_base_url in the Danger Zone. It stays out of the Danger Zone
        # itself (not a secret, no typed confirm needed) so it can render next to
        # misp_api_key instead of being split across two very different sections.
        hot=False,
        help=(
            "This setting is the base URL of your MISP instance, for example "
            "https://misp.example.com. soc-ai builds the MISP client at startup, so "
            "a change needs a restart. Also set the MISP API key in the API keys "
            "panel below."
        ),
    ),
    SettingSpec(
        key="searxng_url",
        attr="searxng_url",
        type="str",
        label="SearXNG base URL",
        section="Web research",
        hot=True,
        help=(
            "This setting is the base URL of your SearXNG instance, for example "
            "https://search.example.com."
        ),
    ),
    SettingSpec(
        key="crawl4ai_enabled",
        attr="crawl4ai_enabled",
        type="bool",
        label="Page read enabled",
        section="Web research",
        hot=True,
        help="soc-ai reads a web page through the crawl4ai instance set below.",
    ),
    SettingSpec(
        key="crawl4ai_url",
        attr="crawl4ai_url",
        type="str",
        label="crawl4ai base URL",
        section="Web research",
        hot=True,
        help=(
            "This setting is the base URL of your crawl4ai instance, for example "
            "https://crawl.example.com."
        ),
    ),
    SettingSpec(
        key="web_search_max_results",
        attr="web_search_max_results",
        type="int",
        label="Maximum web-search results per query",
        section="Web research",
        hot=True,
        help="This setting caps the SearXNG results the agent sees per web_search call.",
        min_value=1,
        max_value=25,
    ),
    # ---- RETRIEVAL (RAG): the opt-in gateway tier for runbook search (hot) ----
    # Both hot=True: search() and the runbook write paths read these fresh from
    # settings per call, so a save applies to the very next lookup. Both default
    # EMPTY = tier off (retrieval stays pure-local FTS5/keyword, zero egress).
    SettingSpec(
        key="rag_embed_model",
        attr="rag_embed_model",
        type="str",
        label="Embeddings model for runbook retrieval",
        section="Retrieval (RAG)",
        hot=True,
        help=(
            "This setting is the OpenAI-compatible /v1/embeddings model id on your "
            "gateway. Empty is the default and turns the semantic tier off. Runbook "
            "search then stays local and uses FTS5. After you change the model, run "
            "Re-embed runbooks below, because the old vectors are stale."
        ),
    ),
    SettingSpec(
        key="rag_rerank_model",
        attr="rag_rerank_model",
        type="str",
        label="Rerank model",
        section="Retrieval (RAG)",
        hot=True,
        help=(
            "This setting is the rerank model id on your gateway. It reranks the "
            "merged keyword candidates and semantic candidates. The gateway must "
            "answer the Cohere-shape /rerank route. Empty is the default and keeps "
            "the weighted merge order. A rerank failure is fail-soft, so search "
            "still answers if the gateway is down."
        ),
    ),
    # ---- MEMORY: deterministic prior-outcome context for synthesis (hot) -----
    # All hot=True: the orchestrator reads these fresh from ctx.settings at the
    # start of every investigation, so a save applies to the very next run.
    # Default OFF pending an anchoring-bias A/B (see the Settings docstrings).
    SettingSpec(
        key="memory_enabled",
        attr="memory_enabled",
        type="bool",
        label="Investigation memory",
        section="Memory",
        hot=True,
        help=(
            "soc-ai shows the verdict synthesis a small block of prior verdicts for "
            "similar alerts. A similar alert shares the rule or an endpoint. The "
            "match is deterministic SQL and uses no embeddings. The block is "
            "context and never evidence, so the citation gate rejects it as "
            "grounding. The default is off until an anchoring-bias A/B test runs."
        ),
    ),
    SettingSpec(
        key="memory_window_days",
        attr="memory_window_days",
        type="int",
        label="Memory window (days)",
        section="Memory",
        hot=True,
        help=(
            "This setting is how far back the prior-outcome lookup searches for a "
            "similar completed investigation. The default is 90 days. A shorter "
            "window forgets faster on a network that changes."
        ),
        min_value=1,
        max_value=365,
    ),
    SettingSpec(
        key="memory_max_items",
        attr="memory_max_items",
        type="int",
        label="Memory items per investigation",
        section="Memory",
        hot=True,
        help=(
            "This setting caps the prior-outcome digests in the round-1 prompt. "
            "Keep the value between 1 and 5. Each item adds anchoring risk and "
            "spends context budget."
        ),
        min_value=1,
        max_value=5,
    ),
    SettingSpec(
        key="memory_include_chat",
        attr="memory_include_chat",
        type="bool",
        label="Include past chat excerpts",
        section="Memory",
        hot=True,
        help=(
            "soc-ai recalls relevant snippets from past chat threads into the "
            "memory block. The snippets are unverified context. A user statement "
            "can be wrong, and nothing in a transcript can ground a verdict. This "
            "setting applies only if investigation memory is on."
        ),
    ),
    # ---- QUALITY: nightly micro-eval trend + alarm tuning (hot) --------------
    # All hot=True: the in-app scheduler loop reads settings fresh each wake,
    # `soc-ai eval-nightly` is a fresh CLI process, and the regression detector
    # reads quality_alarm_drop per run — a console save applies to the very
    # next nightly without touching the running server.
    SettingSpec(
        key="eval_nightly_enabled",
        attr="eval_nightly_enabled",
        type="bool",
        label="Nightly quality eval",
        section="Quality",
        hot=True,
        help=(
            "soc-ai runs the quality micro-eval once a day at the hour below. The "
            "host needs no cron entry. Each run investigates the sample size below "
            "with real model calls. Each run adds one point to the Verdict-quality "
            "trend on the Dashboard and alarms on a regression. If this setting is "
            "off, run the eval from the Run-now button on the Dashboard or from "
            "host cron."
        ),
    ),
    SettingSpec(
        key="eval_nightly_hour_utc",
        attr="eval_nightly_hour_utc",
        type="int",
        label="Nightly eval hour (UTC)",
        section="Quality",
        hot=True,
        help=(
            "This setting is the UTC hour the scheduled eval runs at. The "
            "scheduler wakes at or after this hour, once per UTC day. Pick a quiet "
            "hour, because the eval runs real investigations at concurrency 1."
        ),
        min_value=0,
        max_value=23,
    ),
    SettingSpec(
        key="quality_nightly_n",
        attr="quality_nightly_n",
        type="int",
        label="Nightly eval sample size (alerts per run)",
        section="Quality",
        hot=True,
        help=(
            "This setting is how many real alerts each `soc-ai eval-nightly` run "
            "investigates. Keep the value small, because each alert is a full "
            "investigation. The run is a trend check."
        ),
        min_value=1,
        max_value=10,
    ),
    SettingSpec(
        key="quality_alarm_drop",
        attr="quality_alarm_drop",
        type="float",
        label="Quality alarm: agreement drop threshold",
        section="Quality",
        hot=True,
        help=(
            "This setting is the agreement-rate drop below the trailing 7-run "
            "median that fires the quality_regression alarm. It applies to an "
            "oracle-graded nightly run. A local-mode run alarms on its error rate "
            "and its fallback rate."
        ),
        min_value=0.05,
        max_value=0.5,
    ),
    # ---- DISCOVERY: internal-identifier auto-discovery tuning (hot) ----------
    # All hot=True: the discovery job (CLI / timer / scan-now endpoint) reads
    # these fresh from settings on each run, so a change applies to the next
    # scan without a restart.
    SettingSpec(
        key="discovery_enabled",
        attr="discovery_enabled",
        type="bool",
        label="Internal-identifier discovery enabled",
        section="Discovery",
        hot=True,
        help=(
            "soc-ai learns internal domain suffixes and bare hostnames from "
            "Security Onion data. The Oracle sanitizer then redacts them before "
            "cloud egress. Off skips the scan."
        ),
    ),
    SettingSpec(
        key="discovery_lookback_days",
        attr="discovery_lookback_days",
        type="int",
        label="Discovery lookback window (days)",
        section="Discovery",
        hot=True,
        help=(
            "This setting is how many days of Security Onion events the discovery scan aggregates."
        ),
        min_value=1,
        max_value=90,
    ),
    SettingSpec(
        key="discovery_min_hosts",
        attr="discovery_min_hosts",
        type="int",
        label="Discovery auto-activate threshold (distinct internal hosts)",
        section="Discovery",
        hot=True,
        help=(
            "This setting is the distinct-internal-host count that activates a "
            "candidate. A clearly internal candidate at or above the count becomes "
            "a redaction rule. Below the count the candidate stays a muted "
            "suggestion. A public domain never activates automatically."
        ),
        min_value=1,
        max_value=1000,
    ),
    SettingSpec(
        key="discovery_schedule_enabled",
        attr="discovery_schedule_enabled",
        type="bool",
        label="Run discovery automatically on a schedule",
        section="Discovery",
        hot=True,
        help=(
            "soc-ai runs the internal-identifier scan in the background on the "
            "interval below. Off runs the scan only on demand, from 'Scan now' or "
            "the CLI. The master switch above still applies. This setting applies "
            "live."
        ),
    ),
    SettingSpec(
        key="discovery_schedule_interval_hours",
        attr="discovery_schedule_interval_hours",
        type="int",
        label="Discovery schedule interval (hours)",
        section="Discovery",
        hot=True,
        help=(
            "This setting is the number of hours between automatic scans. The "
            "default is 24 hours. The range is 1 hour to 168 hours."
        ),
        min_value=1,
        max_value=168,
    ),
    # ---- HOST DOSSIER: the self-refreshing asset-context builder -------------
    # Every spec here is hot: the sweep re-reads settings on each wake and the
    # resolver reads its two thresholds per call, so a knob saved here applies to
    # the next build with no restart. That matters more than usual on a Docker
    # deployment, where `docker compose restart` does NOT reload .env — the
    # config console is the only reliable path to these values in production.
    SettingSpec(
        key="dossier_enabled",
        attr="dossier_enabled",
        type="bool",
        label="Host dossier enabled",
        section="Host dossier",
        hot=True,
        help=(
            "soc-ai builds durable per-host asset context and uses it. The context "
            "describes what a host is. Off stops the sweep, the tool and the prompt "
            "block."
        ),
    ),
    SettingSpec(
        key="dossier_schedule_enabled",
        attr="dossier_schedule_enabled",
        type="bool",
        label="Refresh the dossier automatically on a schedule",
        section="Host dossier",
        hot=True,
        help=(
            "soc-ai sweeps the network in the background on the interval below. "
            "Off runs the sweep only on demand, from 'Rebuild now'. The master "
            "switch above still applies. This setting applies live."
        ),
    ),
    SettingSpec(
        key="dossier_schedule_interval_hours",
        attr="dossier_schedule_interval_hours",
        type="int",
        label="Dossier refresh interval (hours)",
        section="Host dossier",
        hot=True,
        help=(
            "This setting is the number of hours between automatic sweeps. The "
            "default is 24 hours. The range is 1 hour to 168 hours."
        ),
        min_value=1,
        max_value=168,
    ),
    SettingSpec(
        key="dossier_lookback_days",
        attr="dossier_lookback_days",
        type="int",
        label="Dossier window (days)",
        section="Host dossier",
        hot=True,
        help=(
            "This setting is how many days of events soc-ai infers each host's "
            "identity and role from. The default is 14 days. 14 days covers two "
            "weekends and two patch cycles, so routine fortnightly activity does "
            "not read as a first-ever event. The hunting layer has its own baseline "
            "window under Behavioural profiles."
        ),
        min_value=1,
        max_value=90,
    ),
    # ── Behavioural profiles ─────────────────────────────────────────────
    # The hunting layer's model of normal. These used to be invisible: zero of
    # 990 config keys matched profile|lead|prior, while a "baseline window"
    # label on the dossier setting above described a different window.
    SettingSpec(
        key="entity_profiles_enabled",
        attr="entity_profiles_enabled",
        type="bool",
        label="Build behavioural profiles",
        section="Behavioural profiles",
        hot=True,
        help=(
            "The dossier sweep builds a per-host model of normal. The model holds "
            "the served ports, the peers, the processes, the active hours and the "
            "connection rate. The role priors and the leads score a departure "
            "against the model. The default is off until you read a shadow week."
        ),
    ),
    SettingSpec(
        key="entity_profile_window_days",
        attr="entity_profile_window_days",
        type="int",
        label="Profile baseline window (days)",
        section="Behavioural profiles",
        hot=True,
        help=(
            "This setting is how many days of history a behavioural baseline "
            "covers. The default is 30 days. 30 days covers four weekends and a "
            "monthly cycle, so a month-end job reads as routine."
        ),
        min_value=7,
        max_value=90,
    ),
    SettingSpec(
        key="entity_profile_lag_hours",
        attr="entity_profile_lag_hours",
        type="int",
        label="Baseline stops this long before now (hours)",
        section="Behavioural profiles",
        hot=True,
        help=(
            "The baseline must not contain the window it is compared against. The "
            "default is 24 hours. 24 hours matches the recent window of the prior "
            "sweep. With no gap the baseline already holds every recent "
            "observation, and nothing can be novel."
        ),
        min_value=0,
        max_value=168,
    ),
    SettingSpec(
        key="dossier_max_hosts_per_run",
        attr="dossier_max_hosts_per_run",
        type="int",
        label="Hosts built per sweep",
        section="Host dossier",
        hot=True,
        help=(
            "This setting caps the hosts one sweep builds. soc-ai builds the "
            "stalest hosts first. The next sweep builds anything over the cap."
        ),
        min_value=1,
        max_value=5000,
    ),
    SettingSpec(
        key="dossier_max_hosts",
        attr="dossier_max_hosts",
        type="int",
        label="Maximum stored dossiers",
        section="Host dossier",
        hot=True,
        help=(
            "This setting caps the rows in the dossier table. A scanned /16 cannot "
            "then fill it. Pruning removes the least-recently-seen hosts, and never "
            "a host with an operator override."
        ),
        min_value=1,
        max_value=100000,
    ),
    SettingSpec(
        key="dossier_min_events",
        attr="dossier_min_events",
        type="int",
        label="Minimum events before inferring a role",
        section="Host dossier",
        hot=True,
        help=(
            "This setting is the event floor for a role. Below the floor in the "
            "window the host's role stays 'unknown'. soc-ai still records the "
            "identity facts."
        ),
        min_value=1,
        max_value=100000,
    ),
    SettingSpec(
        key="dossier_min_confidence",
        attr="dossier_min_confidence",
        type="float",
        label="Minimum confidence to use an inferred value",
        section="Host dossier",
        hot=True,
        help=(
            "This setting is the confidence floor for an inferred value. A value "
            "below the floor resolves to 'unknown' and never prompts about a "
            "conflict. The classifier emits 0.9 for strong evidence and 0.5 for "
            "weak evidence. A floor of 0.6 admits strong evidence only."
        ),
        min_value=0.0,
        max_value=1.0,
    ),
    SettingSpec(
        key="dossier_staleness_hours",
        attr="dossier_staleness_hours",
        type="int",
        label="Inferred values go stale after (hours)",
        section="Host dossier",
        hot=True,
        help=(
            "This setting is the age at which an inferred value goes stale. Past "
            "that age the value resolves to 'unknown'. The default is 72 hours. "
            "72 hours survives one failed sweep."
        ),
        min_value=1,
        max_value=8760,
    ),
    SettingSpec(
        key="dossier_context_enabled",
        attr="dossier_context_enabled",
        type="bool",
        label="Include the dossier in agent prompts",
        section="Host dossier",
        hot=True,
        help=(
            "soc-ai adds host asset context to the investigation, chat and hunt "
            "prompts. This setting is separate from the master switch, so the sweep "
            "can keep building while the context is off."
        ),
    ),
    SettingSpec(
        key="dossier_conflict_min_observations",
        attr="dossier_conflict_min_observations",
        type="int",
        label="Disagreeing builds before prompting about an override",
        section="Host dossier",
        hot=True,
        help=(
            "This setting is how many consecutive builds must disagree with your "
            "override before soc-ai asks you to review it. The count resets to zero "
            "as soon as a build agrees."
        ),
        min_value=1,
        max_value=50,
    ),
    SettingSpec(
        key="dossier_conflict_prompt_interval_hours",
        attr="dossier_conflict_prompt_interval_hours",
        type="int",
        label="Minimum hours between override-conflict prompts",
        section="Host dossier",
        hot=True,
        help=(
            "This setting is the minimum time between two prompts about the same "
            "disagreement. The default is 336 hours, or 14 days. 0 stops every "
            "prompt. A 'keep mine' snooze doubles this interval for each prompt "
            "already sent, up to 90 days."
        ),
        min_value=0,
        max_value=8760,
    ),
    # ---- API KEYS: enrichment provider secrets (write-only) ------------------
    # Distinct from the Danger-Zone secrets: MOST of these feed per-call
    # enrichment clients (read fresh from settings on each tool call / refresh),
    # so they are hot=True — a saved key applies live, no restart. The ONE
    # exception is misp_api_key (hot=False): it is baked into the MispClient built
    # once at startup, so it needs a restart to take effect (see its spec below).
    # secret=True ⇒ Fernet-encrypted at rest, never rendered back (write-only).
    # NOT danger (no typed confirm). Section "API keys" is intentionally NOT in
    # SECTION_ORDER: these render in the dedicated API-keys panel next to Data
    # sources, never in the normal settings groups. Requires CONFIG_SECRET_KEY to
    # persist.
    SettingSpec(
        key="shodan_api_key",
        attr="shodan_api_key",
        type="str",
        section="API keys",
        hot=True,
        secret=True,
        label="Shodan API key",
        help=(
            "This key enables the full Shodan host lookup. Shodan charges for the "
            "key. Online enrichment must also be on."
        ),
    ),
    SettingSpec(
        key="greynoise_api_key",
        attr="greynoise_api_key",
        type="str",
        section="API keys",
        hot=True,
        secret=True,
        label="GreyNoise API key",
        help=(
            "This key enables the scanner-noise lookups. The GreyNoise Community "
            "tier is free. Online enrichment must also be on."
        ),
    ),
    SettingSpec(
        key="misp_api_key",
        attr="misp_api_key",
        type="str",
        section="API keys",
        # Exception to the hot API-keys group: misp_api_key is baked into the
        # MispClient's Authorization header when that client is built once at
        # startup (soc_ai.tools.enrichment.MispClient, held on app.state.misp) and
        # is NOT re-read per call — so a saved key needs a restart to take effect,
        # exactly like misp_url above. The other enrichment keys ARE read per call.
        hot=False,
        secret=True,
        label="MISP API key",
        help=(
            "soc-ai builds the MISP client at startup, so a new key needs a "
            "restart. Also set the MISP URL above under Online enrichment."
        ),
    ),
    SettingSpec(
        key="maxmind_license_key",
        attr="maxmind_license_key",
        type="str",
        section="API keys",
        hot=True,
        secret=True,
        label="MaxMind license key",
        help=(
            "This key refreshes the local GeoLite2 GeoIP and ASN databases. The "
            "next `blocklists refresh` uses it."
        ),
    ),
    SettingSpec(
        key="abuse_ch_auth_key",
        attr="abuse_ch_auth_key",
        type="str",
        section="API keys",
        hot=True,
        secret=True,
        label="abuse.ch auth key",
        help=(
            "This key refreshes the URLhaus and Feodo blocklists. The next "
            "`blocklists refresh` uses it."
        ),
    ),
    SettingSpec(
        key="crawl4ai_token",
        attr="crawl4ai_token",
        type="str",
        section="API keys",
        hot=True,  # read per crawl_page call, never baked into a startup client
        secret=True,
        label="crawl4ai API token",
        help=(
            "This is the bearer token for the crawl4ai instance under Web research "
            "above. Set it if that instance needs authentication. soc-ai stores it "
            "Fernet-encrypted."
        ),
    ),
    # ---- NOTIFICATIONS: opt-in outbound webhook (the only new egress path) ----
    # All hot=True (read fresh per send by soc_ai.notify.fire, so a save applies
    # live). The webhook URL is a secret (Fernet-encrypted, write-only) — but it
    # lives in its OWN "Notifications" section + endpoints, NOT the shared API-keys
    # panel (api_key_specs excludes this section). The master toggle + per-trigger
    # toggles + format + threshold are ordinary non-secret settings that render in
    # the Notifications settings group.
    SettingSpec(
        key="notify_enabled",
        attr="notify_enabled",
        type="bool",
        label="Notifications enabled",
        section="Notifications",
        hot=True,
        # Day1 (final-review I6, curated in as the 8th decision): hot,
        # non-danger, non-secret — passes the invariant test
        # (test_day1_specs_are_hot_and_never_danger_or_secret). The master
        # toggle is the one outbound-egress call worth a day-one look; its
        # per-trigger/format/threshold siblings stay behind Advanced.
        day1=True,
        help=(
            "This setting is the master switch for notifications. Off is the "
            "default and calls no webhook. On lets soc-ai POST a notification to "
            "your webhook on the triggers below. Set the webhook URL separately, "
            "because it is a secret."
        ),
    ),
    SettingSpec(
        key="notify_format",
        attr="notify_format",
        type="str",
        label="Webhook body format",
        section="Notifications",
        hot=True,
        help=(
            "This setting selects the webhook body format. json sends a compact "
            'generic object. slack sends {"text": …}. matrix sends '
            '{"msgtype":"m.text","body":…}. Match the format to your receiver.'
        ),
    ),
    SettingSpec(
        key="notify_verify_ssl",
        attr="notify_verify_ssl",
        type="bool",
        label="Verify the webhook TLS certificate",
        section="Notifications",
        hot=True,
        help=("Turn this off only for an internal receiver with a self-signed certificate."),
    ),
    SettingSpec(
        key="notify_tp_confidence_threshold",
        attr="notify_tp_confidence_threshold",
        type="float",
        label="True-positive notify confidence threshold",
        section="Notifications",
        hot=True,
        help=(
            "This setting is the confidence floor for a true-positive "
            "notification. soc-ai notifies at or above the floor. The default is "
            "0.9 and the range is 0.0 to 1.0."
        ),
        min_value=0.0,
        max_value=1.0,
    ),
    SettingSpec(
        key="notify_on_tp",
        attr="notify_on_tp",
        type="bool",
        label="Notify on high-confidence true-positive",
        section="Notifications",
        hot=True,
        help=(
            "soc-ai notifies on a true-positive verdict at or above the confidence threshold above."
        ),
    ),
    SettingSpec(
        key="notify_on_hunt_threat",
        attr="notify_on_hunt_threat",
        type="bool",
        label="Notify on hunt threat finding",
        section="Notifications",
        hot=True,
        help=("soc-ai notifies if a hunt report holds a finding categorized as a threat."),
    ),
    SettingSpec(
        key="notify_on_model_fitness_fail",
        attr="notify_on_model_fitness_fail",
        type="bool",
        label="Notify on model-fitness FAIL",
        section="Notifications",
        hot=True,
        help=("soc-ai notifies if the analyst-model fitness probe grades the model unfit."),
    ),
    SettingSpec(
        key="notify_on_quality_regression",
        attr="notify_on_quality_regression",
        type="bool",
        label="Notify on nightly quality regression",
        section="Notifications",
        hot=True,
        help=(
            "soc-ai notifies if `soc-ai eval-nightly` detects a verdict-quality "
            "regression. A regression is an agreement drop, an error spike or a "
            "fallback jump against its own history."
        ),
    ),
    SettingSpec(
        key="notify_on_audit_chain_break",
        attr="notify_on_audit_chain_break",
        type="bool",
        label="Notify when the audit trail fails verification",
        section="Notifications",
        hot=True,
        help=(
            "soc-ai notifies if the scheduled check finds the tamper-evident audit "
            "chain broken. The bell in the app reports the break whatever this "
            "setting is."
        ),
    ),
    SettingSpec(
        key="notify_webhook_url",
        attr="notify_webhook_url",
        type="str",
        section="Notifications",
        hot=True,
        secret=True,
        label="Webhook URL",
        help=(
            "This setting is the destination for a notification. soc-ai stores it "
            "Fernet-encrypted and never renders it back. soc-ai sends nothing until "
            "you set it. Use 'Send test' to validate it."
        ),
    ),
    # ---- DANGER ZONE: connection identity + secrets (typed-confirm) ----------
    # The SO/ES/LiteLLM connection settings are hot=False: they feed clients
    # built at startup, so a change needs a restart (the lifespan applies
    # overrides BEFORE building those clients). The PCAP-SSH settings and
    # internal_cidrs are hot=True — they're read fresh per tool-call, so a save
    # applies live. Every danger setting still requires a typed confirm at the
    # route. (crawl4ai_token used to live here too — it moved to the plain
    # hot-secret "API keys" pattern above; see that section's SettingSpec.)
    # How soc-ai logs in to the grid. NOT a Danger-Zone setting: it holds no
    # credential and it names no host, and an operator needs it at the moment an
    # SO upgrade breaks the login, which is the worst moment for a typed
    # confirm. hot=False because the login client is built once at startup.
    SettingSpec(
        key="so_login_flow",
        attr="so_login_flow",
        type="select",
        section="Security Onion",
        hot=False,
        label="Security Onion login flow",
        options=SO_LOGIN_FLOWS,
        help=(
            "How soc-ai logs in to Security Onion. auto: the browser flow, then "
            "the API flow if the browser flow does not complete. browser: SO 3.3 "
            "and later. api: SO 2.4 and 3.0 to 3.2."
        ),
    ),
    SettingSpec(
        key="so_host",
        attr="so_host",
        type="str",
        section="Danger Zone",
        hot=False,
        danger=True,
        label="Security Onion base URL",
        help=(
            "This setting is the Security Onion host soc-ai calls, for example "
            "https://securityonion.example."
        ),
    ),
    SettingSpec(
        key="so_username",
        attr="so_username",
        type="str",
        section="Danger Zone",
        hot=False,
        danger=True,
        label="Security Onion username",
    ),
    SettingSpec(
        key="so_password",
        attr="so_password",
        type="str",
        section="Danger Zone",
        hot=False,
        danger=True,
        secret=True,
        label="Security Onion password",
        help="Stored Fernet-encrypted. Leave blank to keep the current value.",
    ),
    SettingSpec(
        key="so_verify_ssl",
        attr="so_verify_ssl",
        type="bool",
        section="Danger Zone",
        hot=False,
        danger=True,
        label="Verify the Security Onion TLS certificate",
    ),
    SettingSpec(
        key="so_ssh_host",
        attr="so_ssh_host",
        type="str",
        section="Danger Zone",
        hot=True,  # read per PCAP fetch (subprocess), not baked into a startup client
        danger=True,
        label="PCAP sensor SSH host",
        help="This setting is the hostname or IP address of the Security Onion "
        "sensor for live PCAP retrieval. It applies only if PCAP is on. Leave it "
        "blank if PCAP is off.",
    ),
    SettingSpec(
        key="es_hosts",
        attr="es_hosts",
        type="csv",
        section="Danger Zone",
        hot=False,
        danger=True,
        label="Elasticsearch hosts (comma-separated)",
        help=("Write one URL per host. An example is https://es1:9200, https://es2:9200."),
    ),
    SettingSpec(
        key="es_username",
        attr="es_username",
        type="str",
        section="Danger Zone",
        hot=False,
        danger=True,
        label="Elasticsearch username",
    ),
    SettingSpec(
        key="es_password",
        attr="es_password",
        type="str",
        section="Danger Zone",
        hot=False,
        danger=True,
        secret=True,
        label="Elasticsearch password",
        help="Stored Fernet-encrypted. Leave blank to keep the current value.",
    ),
    SettingSpec(
        key="es_verify_ssl",
        attr="es_verify_ssl",
        type="bool",
        section="Danger Zone",
        hot=False,
        danger=True,
        label="Verify the Elasticsearch TLS certificate",
    ),
    SettingSpec(
        key="litellm_base_url",
        attr="litellm_base_url",
        type="str",
        section="Danger Zone",
        hot=False,
        danger=True,
        label="LiteLLM gateway base URL",
        help=(
            "This setting is the model gateway soc-ai calls, for example https://litellm.example."
        ),
    ),
    SettingSpec(
        key="litellm_api_key",
        attr="litellm_api_key",
        type="str",
        section="Danger Zone",
        hot=False,
        danger=True,
        secret=True,
        label="LiteLLM API key",
        help="Stored Fernet-encrypted. Leave blank to keep the current value.",
    ),
    SettingSpec(
        key="internal_cidrs",
        attr="internal_cidrs",
        type="csv",
        section="Danger Zone",
        hot=True,  # read per-call by IP classification / is_internal_ip(settings)
        danger=True,
        label="Internal CIDRs (comma-separated)",
        help=(
            "List the RFC1918 ranges and your own internal ranges. soc-ai "
            "classifies an address as internal or external against this list."
        ),
    ),
    SettingSpec(
        key="so_ssh_user",
        attr="so_ssh_user",
        type="str",
        section="Danger Zone",
        hot=True,  # read per PCAP fetch
        danger=True,
        label="PCAP sensor SSH user",
    ),
    SettingSpec(
        key="so_ssh_key",
        attr="so_ssh_key",
        type="str",
        section="Danger Zone",
        hot=True,  # read per PCAP fetch
        danger=True,
        label="PCAP sensor SSH key path",
        help=("This setting is the path on the soc-ai host to the private key for the PCAP fetch."),
    ),
)

WHITELIST_BY_KEY: dict[str, SettingSpec] = {spec.key: spec for spec in WHITELIST}

# Section display order for the console (grouped by top-level parent — see
# SECTION_PARENTS below; within a parent this tuple is the sub-section order).
SECTION_ORDER: tuple[str, ...] = (
    # Models & Reasoning
    "Agent",
    "Oracle",
    "Quality",
    # Triage & Workflow
    "Triage automation",
    "Hunting",
    "Notifications",
    "Audit trail",
    # Retrieval & Memory
    "Retrieval (RAG)",
    "Memory",
    # Privacy & Egress
    "Discovery",
    "Updates",
    # Data & Enrichment
    "Security Onion",
    "Queries",
    "PCAP",
    "Web research",
    "Online enrichment",
    "Host dossier",
    "Behavioural profiles",
)

# Top-level Config-page information architecture: sub-section → parent header.
# This is the single source of truth for how the server-driven settings groups
# nest on the Config page; GET /config serves each group's parent so the
# frontend never hardcodes a divergent copy of this map. (The frontend's own
# standalone panels — Data sources, Egress policy, Users, … — declare their
# parent client-side, since they don't originate from SettingSpec sections.)
SECTION_PARENTS: dict[str, str] = {
    "Agent": "Models & Reasoning",
    "Oracle": "Models & Reasoning",
    # Quality lives with the model knobs: the nightly micro-eval measures the
    # very thing the Agent/Oracle sections configure (verdict honesty), and its
    # alarm is the tripwire for a bad analyst_model / engine swap.
    "Quality": "Models & Reasoning",
    "Triage automation": "Triage & Workflow",
    # The hunting settings govern what the catalog sweep records, which is
    # the workflow the Hunts page reads. They sit beside the sweep switches
    # that start it.
    "Hunting": "Triage & Workflow",
    "Notifications": "Triage & Workflow",
    # The audit trail records what the workflow did and who approved it, and
    # its alarm goes out over the notification webhook configured just above —
    # so it sits with the workflow settings rather than off in a diagnostics
    # corner an operator visits once.
    "Audit trail": "Triage & Workflow",
    "Retrieval (RAG)": "Retrieval & Memory",
    "Memory": "Retrieval & Memory",
    "Discovery": "Privacy & Egress",
    "Updates": "Privacy & Egress",
    "Security Onion": "Data & Enrichment",
    "Queries": "Data & Enrichment",
    "PCAP": "Data & Enrichment",
    "Web research": "Data & Enrichment",
    "Online enrichment": "Data & Enrichment",
    # The dossier is enrichment that runs against the grid's own data rather
    # than a third party, so it sits beside the other data sources — not under
    # Privacy & Egress with Discovery, whose job is deciding what gets redacted.
    "Host dossier": "Data & Enrichment",
    "Behavioural profiles": "Data & Enrichment",
}


def is_editable(key: str) -> bool:
    """True iff *key* is in the admin-editable whitelist."""
    return key in WHITELIST_BY_KEY


def api_key_specs() -> tuple[SettingSpec, ...]:
    """The hot, write-only API-key specs surfaced by the dedicated API-keys panel.

    These are the secret, non-danger provider keys (enrichment) — distinct from
    the restart-required Danger-Zone connection secrets (SO/ES/LiteLLM) AND from
    the Notifications webhook secret (which lives in its own Notifications section
    + dedicated endpoints, not the shared API-keys panel).
    """
    return tuple(s for s in WHITELIST if s.secret and not s.danger and s.section != "Notifications")


def notify_webhook_spec() -> SettingSpec:
    """The write-only, Fernet-encrypted webhook-URL secret spec (Notifications)."""
    return WHITELIST_BY_KEY["notify_webhook_url"]


def _coerce_bool(raw: str) -> bool:
    return raw.strip().lower() in ("on", "true", "1", "yes", "checked")


def _check_bounds(spec: SettingSpec, value: float) -> None:
    """Raise ValueError if a numeric *value* falls outside the spec's bounds."""
    if spec.min_value is not None and value < spec.min_value:
        raise ValueError(f"{spec.key} must be >= {spec.min_value}")
    if spec.max_value is not None and value > spec.max_value:
        raise ValueError(f"{spec.key} must be <= {spec.max_value}")


# URL-valued settings. An admin may legitimately point these at an internal
# service (self-hosted SearXNG/crawl4ai, the SO/ES/gateway hosts), so the HOST is
# intentional and NOT restricted — only the scheme is, to block file://, gopher://
# and similar SSRF vectors. Empty (unset) is always allowed.
_URL_SETTING_KEYS = frozenset(
    {"searxng_url", "crawl4ai_url", "so_host", "es_hosts", "litellm_base_url", "misp_url"}
)


def _require_http_scheme(key: str, value: str) -> None:
    for part in value.split(","):  # es_hosts may be a CSV of URLs
        v = part.strip()
        if not v:
            continue
        scheme = urlparse(v).scheme.lower()
        if scheme not in ("http", "https"):
            raise ValueError(f"{key} must be an http(s) URL (got scheme {scheme or 'none'!r})")


def coerce(key: str, raw_str: str) -> Any:
    """Coerce a raw form string to the declared type for *key*.

    Checkbox semantics for bool: HTML checkboxes submit ``on`` when checked and
    submit nothing when unchecked, so an absent value (empty string) is False.
    Raises ``KeyError`` if *key* is not whitelisted, ``ValueError`` on a value
    that won't coerce to the declared type OR falls outside its bounds.
    """
    spec = WHITELIST_BY_KEY[key]  # KeyError → caller rejects non-whitelisted key
    if spec.type == "bool":
        return _coerce_bool(raw_str)
    if spec.type == "float":
        v = float(raw_str)  # ValueError on junk → caller rejects
        _check_bounds(spec, v)
        return v
    if spec.type == "int":
        v_int = int(raw_str)  # ValueError on junk/"1.5" → caller rejects
        _check_bounds(spec, v_int)
        return v_int
    # URL-scheme guard for BOTH csv (es_hosts) and plain-str URL settings. Runs
    # BEFORE the csv early-return below — otherwise it is dead for es_hosts, the
    # only csv-typed URL setting, and a bare host:port ("es1:9200") is stored then
    # rejected by AnyHttpUrl on every restart. _require_http_scheme splits on
    # commas, so the raw csv string is checked host-by-host.
    if key in _URL_SETTING_KEYS:
        _require_http_scheme(key, raw_str)
    if spec.type == "csv":
        # Comma-separated list → list[str]; whitespace trimmed, empties dropped.
        return [part.strip() for part in raw_str.split(",") if part.strip()]
    if spec.type == "select":
        v_sel = str(raw_str).strip()
        if not spec.options or v_sel not in spec.options:
            raise ValueError(f"{spec.key} must be one of {list(spec.options or ())}")
        return v_sel
    return str(raw_str)


def _validate_typed(spec: SettingSpec, value: Any) -> Any:
    """Validate/normalise an already-typed value against the spec's type."""
    if spec.type == "bool":
        if not isinstance(value, bool):
            raise ValueError(f"{spec.key} expects a bool")
        return value
    if spec.type == "float":
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"{spec.key} expects a number")
        _check_bounds(spec, float(value))
        return float(value)
    if spec.type == "int":
        # bool is an int subclass — reject it explicitly. Accept a whole-valued
        # float (JSON round-trips ints that were stored as e.g. 24.0).
        if isinstance(value, bool):
            raise ValueError(f"{spec.key} expects an integer")
        if isinstance(value, float) and value.is_integer():
            value = int(value)
        if not isinstance(value, int):
            raise ValueError(f"{spec.key} expects an integer")
        _check_bounds(spec, value)
        return value
    if spec.type == "csv":
        if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
            raise ValueError(f"{spec.key} expects a list of strings")
        cleaned = [x.strip() for x in value if x.strip()]
        # es_hosts is a csv of URLs — enforce the http(s) scheme here too, not
        # just the plain-str branch below (which the csv return would skip).
        if spec.key in _URL_SETTING_KEYS:
            _require_http_scheme(spec.key, ",".join(cleaned))
        return cleaned
    if not isinstance(value, str):
        raise ValueError(f"{spec.key} expects a string")
    if spec.type == "select" and (not spec.options or value not in spec.options):
        raise ValueError(f"{spec.key} must be one of {list(spec.options or ())}")
    if spec.key in _URL_SETTING_KEYS:
        _require_http_scheme(spec.key, value)
    return value


async def load_overrides(db: AsyncSession) -> dict[str, Any]:
    """Read all override rows, JSON-decoding each value.

    Rows for keys no longer whitelisted are skipped (defensive — a removed key
    in an old DB must not crash startup).
    """
    rows = (await db.scalars(select(ConfigOverride))).all()
    out: dict[str, Any] = {}
    for row in rows:
        if row.key not in WHITELIST_BY_KEY:
            continue
        try:
            out[row.key] = json.loads(row.value)
        except (ValueError, TypeError):
            continue
    return out


async def set_override(
    db: AsyncSession,
    key: str,
    value: Any,
    *,
    updated_by: int | None,
    secret_box: SecretBox | None = None,
) -> None:
    """Upsert an override row for a whitelisted *key*.

    *value* must already be the declared type (use :func:`coerce` on form
    input first). For a ``secret`` spec the value is Fernet-encrypted before
    storage (so a DB dump never reveals it) — this requires *secret_box*.
    Raises ``KeyError`` for a non-whitelisted key, ``ValueError`` for a value of
    the wrong type or a missing ``secret_box`` on a secret key.
    """
    spec = WHITELIST_BY_KEY[key]  # KeyError → caller rejects
    typed = _validate_typed(spec, value)
    if spec.secret:
        if secret_box is None:
            raise ValueError(f"{spec.key} is a secret but no config_secret_key is set")
        # Store the Fernet token (a str) as JSON — load_overrides reads it back
        # as the token; apply_to_settings decrypts it.
        encoded = json.dumps(secret_box.encrypt(str(typed)))
    else:
        encoded = json.dumps(typed)
    row = await db.get(ConfigOverride, key)
    if row is None:
        db.add(ConfigOverride(key=key, value=encoded, updated_by=updated_by))
    else:
        row.value = encoded
        row.updated_by = updated_by
    await db.commit()


async def delete_override(db: AsyncSession, key: str) -> None:
    """Remove an override row, reverting *key* to its env/default value.

    Note: this only removes the persisted override; the live setting is not
    reset to the env value until the next restart (or an explicit re-apply by
    the caller). No-op if no row exists.
    """
    row = await db.get(ConfigOverride, key)
    if row is not None:
        await db.delete(row)
        await db.commit()


def apply_to_settings(
    settings: Settings,
    overrides: dict[str, Any],
    *,
    secret_box: SecretBox | None = None,
) -> list[str]:
    """Apply whitelisted overrides onto the live Settings singleton.

    For each whitelisted key present in *overrides*, ``setattr`` the typed value
    onto the Settings attribute. ``Settings`` uses ``validate_assignment`` so the
    assignment coerces to the field's real type (str→AnyHttpUrl/SecretStr,
    list→typed list). Secret values are Fernet-decrypted first (needs
    *secret_box*); a secret override with no usable box, a decrypt failure, or a
    value that fails validation is skipped defensively (the env value stands) so
    a bad override never crashes startup.

    Returns the list of keys that were ACTUALLY applied. A caller doing an
    interactive single-key hot-apply (``POST /config/setting``) uses this to tell
    a silently-skipped value (type-correct but rejected by a field validator or
    cross-field constraint at assignment time) from a successful save, instead of
    reporting ``ok`` on a value that never took and would re-skip every restart.

    A rejected value never reaches the live object. ``validate_assignment`` runs
    the model validators AFTER the field has been set, and pydantic does not put
    the old value back when one of them raises, so assigning straight onto
    *settings* left the bad value there while reporting the key as not applied.
    From then on every later assignment re-ran the same validator and failed too,
    naming the setting that was stuck rather than the one being changed: one bad
    value bricked configuration on that instance and misdirected whoever tried to
    work out why. Each assignment is proved on a throwaway copy first, which is
    the pattern ``POST /config/setting`` and the Danger Zone save already use;
    the shared path now does it too.
    """
    applied: list[str] = []
    for key, value in overrides.items():
        spec = WHITELIST_BY_KEY.get(key)
        if spec is None:
            continue
        try:
            if spec.secret:
                if secret_box is None:
                    continue  # can't decrypt → leave the env-configured secret
                typed: Any = secret_box.decrypt(str(value))  # → plaintext str
            else:
                typed = _validate_typed(spec, value)
            # The copy carries every override applied so far, so cross-field
            # constraints see the same state the real assignment will.
            setattr(settings.model_copy(), spec.attr, typed)
        except (ValueError, TypeError, PydanticValidationError):
            _LOGGER.warning("skipping config override %s (invalid value)", key)
            continue
        # Proved on the copy, so this cannot leave the live object half-written.
        setattr(settings, spec.attr, typed)
        applied.append(key)
    return applied
