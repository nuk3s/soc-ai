"""Admin-editable Settings overlay (the hot-apply core).

A small, explicit whitelist of :class:`~soc_ai.config.Settings` attributes may
be overridden at runtime by an admin via the config console. Overrides are
JSON-encoded scalars persisted in the ``config_overrides`` table; they are
re-applied to ``app.state.settings`` at startup so they survive restarts, and
hot-applied via ``setattr`` immediately on save when the field is marked hot.

SECURITY: the whitelist contains NO secret/connection fields (passwords,
api-keys, hosts). Secrets are never written to the DB and never echoed in a
response body. Connection/secret settings are display-only (masked) in inc1.
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

from soc_ai.config import Settings
from soc_ai.store.models import ConfigOverride
from soc_ai.store.secret_box import SecretBox

_LOGGER = logging.getLogger(__name__)

SettingType = Literal["bool", "str", "float", "int", "csv"]


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


# The whitelist of admin-editable settings. Order is display order within a
# section. Every field listed here MUST exist on Settings and MUST NOT be a
# secret. All inc1 keys are hot (applied live on save).
WHITELIST: tuple[SettingSpec, ...] = (
    SettingSpec(
        key="oracle_enabled",
        attr="oracle_enabled",
        type="bool",
        label="Oracle enabled (cloud frontier adjudication)",
        section="Oracle",
        hot=True,
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
        label="Escalate when local verdict is needs_more_info",
        section="Oracle",
        hot=True,
    ),
    SettingSpec(
        key="oracle_escalate_malware_non_tp",
        attr="oracle_escalate_malware_non_tp",
        type="bool",
        label="Escalate malware/exploit alerts that aren't high-confidence TP",
        section="Oracle",
        hot=True,
    ),
    SettingSpec(
        key="oracle_escalate_below_confidence",
        attr="oracle_escalate_below_confidence",
        type="float",
        label="Escalate when local confidence is below",
        section="Oracle",
        hot=True,
        help="Local verdicts under this confidence (0-1) are sent to the Oracle.",
        min_value=0.0,
        max_value=1.0,
    ),
    SettingSpec(
        key="oracle_skip_after_confident_loop",
        attr="oracle_skip_after_confident_loop",
        type="float",
        label="Trust a confident loop verdict (skip Oracle) at/above",
        section="Oracle",
        hot=True,
        help=(
            "After a real investigation loop runs, a malware/attack verdict at or "
            "above this confidence (0-1) is trusted locally - no Oracle double-check."
        ),
        min_value=0.0,
        max_value=1.0,
    ),
    SettingSpec(
        key="fast_triage_enabled",
        attr="fast_triage_enabled",
        type="bool",
        label="Fast triage (skip tools when confident)",
        section="Agent",
        hot=True,
        help=(
            "Saves time but can yield shallower results — the agent may finalize "
            "a confident first-pass verdict with few or no tool calls. Turn off to "
            "always investigate with the full tool-driven loop."
        ),
    ),
    SettingSpec(
        key="investigate_when_unsure",
        attr="investigate_when_unsure",
        type="bool",
        label="Investigate when round-1 verdict isn't evidence-backed",
        section="Agent",
        hot=True,
        help="Run the real tool-driven loop instead of a zero-tool synth guess.",
    ),
    SettingSpec(
        key="webui_extra_detections",
        attr="webui_extra_detections",
        type="bool",
        label="Show non-Suricata SO detections in the feed",
        section="Agent",
        hot=True,
        help="Union Sigma hits + Zeek ATTACK notices into the alerts feed (tagged by kind).",
    ),
    SettingSpec(
        key="analyst_model",
        attr="analyst_model",
        type="str",
        label="Analyst model",
        section="Agent",
        hot=True,
        help="LiteLLM model the analyst agent uses for every triage. A bad value fails hunts.",
    ),
    SettingSpec(
        key="host_risk_window_hours",
        attr="host_risk_window_hours",
        type="int",
        label="Host-risk window (hours, each side)",
        section="Agent",
        hot=True,
        help=(
            "Wide ±N-hour window for the host-risk profile (the endpoint's recent "
            "alert histogram that flags a compromised host). 0 disables it."
        ),
        min_value=0,
        max_value=168,
    ),
    SettingSpec(
        key="agent_tool_calls_limit",
        attr="agent_tool_calls_limit",
        type="int",
        label="Max tool calls per investigation",
        section="Agent",
        hot=True,
        help="Hard cap on tool calls before the investigation loop is cut off.",
        min_value=1,
        max_value=200,
    ),
    SettingSpec(
        key="agent_request_limit",
        attr="agent_request_limit",
        type="int",
        label="Max model requests per investigation",
        section="Agent",
        hot=True,
        help="Hard cap on model round-trips per investigation.",
        min_value=1,
        max_value=100,
    ),
    SettingSpec(
        key="synthesizer_temperature",
        attr="synthesizer_temperature",
        type="float",
        label="Synthesizer temperature (verdict determinism)",
        section="Agent",
        hot=True,
        help="Lower = more deterministic verdicts. 0.2 is the tuned default.",
        min_value=0.0,
        max_value=2.0,
    ),
    SettingSpec(
        key="investigator_temperature",
        attr="investigator_temperature",
        type="float",
        label="Investigator temperature (exploration)",
        section="Agent",
        hot=True,
        help="Higher = more exploratory tool use. 0.4 is the tuned default.",
        min_value=0.0,
        max_value=2.0,
    ),
    SettingSpec(
        key="auto_triage_max_targets",
        attr="auto_triage_max_targets",
        type="int",
        label="Auto-triage max alerts per run",
        section="Agent",
        hot=True,
        help="Cap on how many alerts a single ⚡ auto-triage run will hunt.",
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
        help="Retries on transient gateway errors (rides out brief proxy blips).",
        min_value=0,
        max_value=10,
    ),
    SettingSpec(
        key="auto_ack_fp_enabled",
        attr="auto_ack_fp_enabled",
        type="bool",
        label="Auto-acknowledge high-confidence false positives",
        section="Agent",
        hot=True,
        help=(
            "When on, a completed investigation with verdict=false_positive at or above "
            "the threshold below is automatically acknowledged in Security Onion. "
            "Off by default — this writes to SO without analyst review."
        ),
    ),
    SettingSpec(
        key="auto_ack_fp_threshold",
        attr="auto_ack_fp_threshold",
        type="float",
        label="Auto-ack confidence threshold (FP only)",
        section="Agent",
        hot=True,
        help="Minimum confidence for auto-ack. Recommended: 0.7. Range: 0.0-1.0.",
        min_value=0.0,
        max_value=1.0,
    ),
    SettingSpec(
        key="auto_triage_min_severity",
        attr="auto_triage_min_severity",
        type="str",
        label="Auto-triage minimum severity",
        section="Agent",
        hot=True,
        help=(
            "Sweeps triage this severity and above (critical, high, medium, low). "
            "Default: high — triages critical and high detections. "
            "Set to medium to also include medium-severity detections."
        ),
    ),
    SettingSpec(
        key="synth_first_pipeline",
        attr="synth_first_pipeline",
        type="bool",
        label="Synth-first pipeline",
        section="Agent",
        hot=True,
        help=(
            "Route alerts through the synth-first A→B→C→D pipeline (the default). "
            "Off A/B-tests the legacy two-stage investigator pipeline."
        ),
    ),
    SettingSpec(
        key="enable_rule_class_fast_path",
        attr="enable_rule_class_fast_path",
        type="bool",
        label="Rule-class fast path",
        section="Agent",
        hot=True,
        help=(
            "Route informational/low-severity alerts through a stripped-down "
            "confirm-benign prompt with a tighter tool budget. Off runs the full "
            "pipeline for every alert."
        ),
    ),
    SettingSpec(
        key="synthesis_confidence_floor",
        attr="synthesis_confidence_floor",
        type="float",
        label="Synthesis confidence floor (retask below)",
        section="Agent",
        hot=True,
        help=(
            "A synthesizer verdict under this confidence (0-1) retasks the "
            "investigator once with the open questions. 0.6 is the tuned default."
        ),
        min_value=0.0,
        max_value=1.0,
    ),
    SettingSpec(
        key="fast_path_synthesis_floor",
        attr="fast_path_synthesis_floor",
        type="float",
        label="Fast-path confidence floor",
        section="Agent",
        hot=True,
        help=(
            "Lower confidence floor on the fast path - informational alerts rarely "
            "benefit from a retask, so ≥0.4 passes through. Range 0-1."
        ),
        min_value=0.0,
        max_value=1.0,
    ),
    SettingSpec(
        key="fast_path_sampling_rate",
        attr="fast_path_sampling_rate",
        type="float",
        label="Fast-path full-pipeline sampling rate",
        section="Agent",
        hot=True,
        help=(
            "Fraction (0-1) of fast-path-eligible alerts routed through the FULL "
            "pipeline anyway, for drift monitoring. 0 disables sampling."
        ),
        min_value=0.0,
        max_value=1.0,
    ),
    SettingSpec(
        key="investigator_max_response_tokens",
        attr="investigator_max_response_tokens",
        type="int",
        label="Investigator max response tokens (per turn)",
        section="Agent",
        hot=True,
        help=(
            "Caps reasoning + content per investigator turn so a chatty turn can't "
            "dominate wall-clock. 32000 is the calibrated default."
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
        help=(
            "Wildcard ES index/alias pattern for SO events (e.g. *:so-* or logs-*). "
            "Used by every alert/event query."
        ),
    ),
    SettingSpec(
        key="cases_index_pattern",
        attr="cases_index_pattern",
        type="str",
        label="Cases index pattern",
        section="Queries",
        hot=True,
        help="Wildcard ES index/alias pattern for SO cases (e.g. *:so-case-*).",
    ),
    SettingSpec(
        key="detections_index_pattern",
        attr="detections_index_pattern",
        type="str",
        label="Detections index pattern",
        section="Queries",
        hot=True,
        help="Wildcard ES index/alias pattern for SO detections (e.g. *:so-detection-*).",
    ),
    SettingSpec(
        key="playbooks_index_pattern",
        attr="playbooks_index_pattern",
        type="str",
        label="Playbooks index pattern",
        section="Queries",
        hot=True,
        help="Wildcard ES index/alias pattern for SO playbooks (e.g. *:so-playbook-*).",
    ),
    SettingSpec(
        key="webui_alerts_query",
        attr="webui_alerts_query",
        type="str",
        label="Web-UI alerts feed query (OQL)",
        section="Queries",
        hot=True,
        help=(
            "OQL filter selecting which events appear in the alerts feed "
            "(default tags:alert). Read fresh on every feed fetch."
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
            "How far back a prior verdict on a matching (rule, src, dst) flow is "
            "inherited onto a new alert in the feed."
        ),
        min_value=0,
        max_value=365,
    ),
    SettingSpec(
        key="pcap_enabled",
        attr="pcap_enabled",
        type="bool",
        label="PCAP retrieval enabled (SSH + suripcap)",
        section="PCAP",
        hot=True,
    ),
    SettingSpec(
        key="web_search_enabled",
        attr="web_search_enabled",
        type="bool",
        label="Web search enabled (SearXNG)",
        section="Web research",
        hot=True,
    ),
    SettingSpec(
        key="searxng_url",
        attr="searxng_url",
        type="str",
        label="SearXNG base URL (e.g. https://search.example.com)",
        section="Web research",
        hot=True,
    ),
    SettingSpec(
        key="crawl4ai_enabled",
        attr="crawl4ai_enabled",
        type="bool",
        label="Page read enabled (crawl4ai)",
        section="Web research",
        hot=True,
    ),
    SettingSpec(
        key="crawl4ai_url",
        attr="crawl4ai_url",
        type="str",
        label="crawl4ai base URL (e.g. https://crawl.example.com)",
        section="Web research",
        hot=True,
    ),
    SettingSpec(
        key="web_search_max_results",
        attr="web_search_max_results",
        type="int",
        label="Max web-search results per query",
        section="Web research",
        hot=True,
        help="How many SearXNG results the agent sees per web_search call.",
        min_value=1,
        max_value=25,
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
            "Learn internal domain suffixes + bare hostnames from SO data so the "
            "Oracle sanitizer redacts them before cloud egress. Off skips the scan."
        ),
    ),
    SettingSpec(
        key="discovery_lookback_days",
        attr="discovery_lookback_days",
        type="int",
        label="Discovery lookback window (days)",
        section="Discovery",
        hot=True,
        help="How many days of SO events the discovery scan aggregates over.",
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
            "Distinct-internal-host count at/above which a clearly-internal "
            "candidate auto-activates as a redaction rule. Below it, the "
            "candidate is a muted suggestion. A public domain never auto-activates."
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
            "Run the internal-identifier scan automatically in the background "
            "on the interval below. Off runs it only on demand ('Scan now' / CLI). "
            "Honors the master switch above. Takes effect live."
        ),
    ),
    SettingSpec(
        key="discovery_schedule_interval_hours",
        attr="discovery_schedule_interval_hours",
        type="int",
        label="Discovery schedule interval (hours)",
        section="Discovery",
        hot=True,
        help="Hours between automatic scans (1-168). Default 24 (daily).",
        min_value=1,
        max_value=168,
    ),
    # ---- DANGER ZONE: connection identity + secrets (restart-required) -------
    # All hot=False: these feed clients built at startup, so a change takes
    # effect on the next restart (the lifespan applies overrides BEFORE building
    # the SO/ES/LiteLLM clients). Each requires a typed confirm at the route.
    SettingSpec(
        key="so_host",
        attr="so_host",
        type="str",
        section="Danger Zone",
        hot=False,
        danger=True,
        label="Security Onion base URL",
        help="e.g. https://securityonion.example — the SO/Kibana host soc-ai talks to.",
    ),
    SettingSpec(
        key="so_username",
        attr="so_username",
        type="str",
        section="Danger Zone",
        hot=False,
        danger=True,
        label="SO username",
    ),
    SettingSpec(
        key="so_password",
        attr="so_password",
        type="str",
        section="Danger Zone",
        hot=False,
        danger=True,
        secret=True,
        label="SO password",
        help="Stored Fernet-encrypted. Leave blank to keep the current value.",
    ),
    SettingSpec(
        key="so_verify_ssl",
        attr="so_verify_ssl",
        type="bool",
        section="Danger Zone",
        hot=False,
        danger=True,
        label="Verify SO TLS certificate",
    ),
    SettingSpec(
        key="so_ssh_host",
        attr="so_ssh_host",
        type="str",
        section="Danger Zone",
        hot=False,
        danger=True,
        label="PCAP sensor SSH host",
        help="Hostname/IP of the SO sensor for live PCAP retrieval. Only used when "
        "PCAP is enabled; leave blank if PCAP is off.",
    ),
    SettingSpec(
        key="es_hosts",
        attr="es_hosts",
        type="csv",
        section="Danger Zone",
        hot=False,
        danger=True,
        label="Elasticsearch hosts (comma-separated)",
        help="e.g. https://es1:9200, https://es2:9200",
    ),
    SettingSpec(
        key="es_username",
        attr="es_username",
        type="str",
        section="Danger Zone",
        hot=False,
        danger=True,
        label="ES username",
    ),
    SettingSpec(
        key="es_password",
        attr="es_password",
        type="str",
        section="Danger Zone",
        hot=False,
        danger=True,
        secret=True,
        label="ES password",
        help="Stored Fernet-encrypted. Leave blank to keep the current value.",
    ),
    SettingSpec(
        key="es_verify_ssl",
        attr="es_verify_ssl",
        type="bool",
        section="Danger Zone",
        hot=False,
        danger=True,
        label="Verify ES TLS certificate",
    ),
    SettingSpec(
        key="litellm_base_url",
        attr="litellm_base_url",
        type="str",
        section="Danger Zone",
        hot=False,
        danger=True,
        label="LiteLLM gateway base URL",
        help="e.g. https://litellm.example — the model gateway soc-ai calls.",
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
        hot=False,
        danger=True,
        label="Internal CIDRs (comma-separated)",
        help="RFC1918 + your internal ranges; used to classify internal vs external.",
    ),
    SettingSpec(
        key="so_ssh_host",
        attr="so_ssh_host",
        type="str",
        section="Danger Zone",
        hot=False,
        danger=True,
        label="PCAP sensor SSH host",
    ),
    SettingSpec(
        key="so_ssh_user",
        attr="so_ssh_user",
        type="str",
        section="Danger Zone",
        hot=False,
        danger=True,
        label="PCAP sensor SSH user",
    ),
    SettingSpec(
        key="so_ssh_key",
        attr="so_ssh_key",
        type="str",
        section="Danger Zone",
        hot=False,
        danger=True,
        label="PCAP sensor SSH key path",
        help="Path on the soc-ai host to the private key used for PCAP fetch.",
    ),
    SettingSpec(
        key="crawl4ai_token",
        attr="crawl4ai_token",
        type="str",
        section="Danger Zone",
        hot=False,
        danger=True,
        secret=True,
        label="crawl4ai API token",
        help="Stored Fernet-encrypted. Leave blank to keep the current value.",
    ),
)

WHITELIST_BY_KEY: dict[str, SettingSpec] = {spec.key: spec for spec in WHITELIST}

# Section display order for the console.
SECTION_ORDER: tuple[str, ...] = (
    "Oracle",
    "Agent",
    "Queries",
    "PCAP",
    "Web research",
    "Discovery",
)


def is_editable(key: str) -> bool:
    """True iff *key* is in the admin-editable whitelist."""
    return key in WHITELIST_BY_KEY


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
    {"searxng_url", "crawl4ai_url", "so_host", "es_hosts", "litellm_base_url"}
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
    if spec.type == "csv":
        # Comma-separated list → list[str]; whitespace trimmed, empties dropped.
        return [part.strip() for part in raw_str.split(",") if part.strip()]
    result = str(raw_str)
    if key in _URL_SETTING_KEYS:
        _require_http_scheme(key, result)
    return result


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
        return [x.strip() for x in value if x.strip()]
    if not isinstance(value, str):
        raise ValueError(f"{spec.key} expects a string")
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
) -> None:
    """Apply whitelisted overrides onto the live Settings singleton.

    For each whitelisted key present in *overrides*, ``setattr`` the typed value
    onto the Settings attribute. ``Settings`` uses ``validate_assignment`` so the
    assignment coerces to the field's real type (str→AnyHttpUrl/SecretStr,
    list→typed list). Secret values are Fernet-decrypted first (needs
    *secret_box*); a secret override with no usable box, a decrypt failure, or a
    value that fails validation is skipped defensively (the env value stands) so
    a bad override never crashes startup.
    """
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
            setattr(settings, spec.attr, typed)
        except (ValueError, PydanticValidationError):
            _LOGGER.warning("skipping config override %s (invalid value)", key)
            continue
