"""Tests for :mod:`soc_ai.config`."""

from __future__ import annotations

from ipaddress import IPv4Network
from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError
from soc_ai.config import Settings, get_settings


def _setenv_required(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SO_HOST", "https://so.example.com")
    monkeypatch.setenv("SO_USERNAME", "analyst")
    monkeypatch.setenv("SO_PASSWORD", "password123")
    monkeypatch.setenv("ES_HOSTS", "https://so.example.com:9200")
    monkeypatch.setenv("LITELLM_BASE_URL", "http://localhost:4000")


def test_settings_loads_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    _setenv_required(monkeypatch)
    s = Settings()
    assert str(s.so_host).startswith("https://so.example.com")
    assert s.so_username == "analyst"
    assert isinstance(s.so_password, SecretStr)
    assert s.so_password.get_secret_value() == "password123"
    assert len(s.es_hosts) == 1


def test_analyst_model_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    _setenv_required(monkeypatch)
    monkeypatch.setenv("ANALYST_MODEL", "my-real-model")
    assert Settings().analyst_model == "my-real-model"


def test_heavy_model_is_deprecated_alias(monkeypatch: pytest.MonkeyPatch) -> None:
    """The old HEAVY_MODEL env var still populates analyst_model (back-compat)."""
    _setenv_required(monkeypatch)
    monkeypatch.setenv("HEAVY_MODEL", "legacy-named-model")
    assert Settings().analyst_model == "legacy-named-model"


def test_audit_redact_defaults_on(monkeypatch: pytest.MonkeyPatch) -> None:
    """Audit redaction is default-on (shared ES cluster; secret-shape only)."""
    _setenv_required(monkeypatch)
    assert Settings().audit_redact is True


def test_missing_required_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SO_HOST", "https://so.example.com")
    # SO_USERNAME, SO_PASSWORD, ES_HOSTS, LITELLM_BASE_URL all missing
    with pytest.raises(ValidationError) as excinfo:
        Settings()
    missing_fields = {err["loc"][0] for err in excinfo.value.errors()}
    assert "so_username" in missing_fields
    assert "so_password" in missing_fields
    assert "es_hosts" in missing_fields
    assert "litellm_base_url" in missing_fields


def test_so_ssh_host_defaults_empty_no_lab_ip(monkeypatch: pytest.MonkeyPatch) -> None:
    """The package ships no environment-specific sensor IP (pcap off by default)."""
    _setenv_required(monkeypatch)
    s = Settings()
    assert s.so_ssh_host == ""
    assert s.pcap_enabled is False


def test_pcap_enabled_requires_ssh_host(monkeypatch: pytest.MonkeyPatch) -> None:
    """Enabling PCAP without a sensor host fails fast at startup."""
    _setenv_required(monkeypatch)
    monkeypatch.setenv("PCAP_ENABLED", "true")
    with pytest.raises(ValidationError) as excinfo:
        Settings()
    assert "SO_SSH_HOST" in str(excinfo.value)
    # ...and it's satisfied once the host is provided
    monkeypatch.setenv("SO_SSH_HOST", "sensor.example.com")
    assert Settings().so_ssh_host == "sensor.example.com"


def test_es_hosts_csv_parsing(monkeypatch: pytest.MonkeyPatch) -> None:
    _setenv_required(monkeypatch)
    monkeypatch.setenv("ES_HOSTS", "https://a.example.com:9200,https://b.example.com:9200")
    s = Settings()
    assert len(s.es_hosts) == 2
    assert any("a.example.com" in str(h) for h in s.es_hosts)
    assert any("b.example.com" in str(h) for h in s.es_hosts)


def test_internal_cidrs_csv_parsing(monkeypatch: pytest.MonkeyPatch) -> None:
    _setenv_required(monkeypatch)
    monkeypatch.setenv("INTERNAL_CIDRS", "10.0.0.0/8,172.16.0.0/12")
    s = Settings()
    assert IPv4Network("10.0.0.0/8") in s.internal_cidrs
    assert IPv4Network("172.16.0.0/12") in s.internal_cidrs


def test_internal_cidrs_default(monkeypatch: pytest.MonkeyPatch) -> None:
    _setenv_required(monkeypatch)
    s = Settings()
    # RFC1918 trio comes from defaults.
    assert len(s.internal_cidrs) == 3
    assert IPv4Network("192.168.0.0/16") in s.internal_cidrs


def test_use_connect_api_false_when_not_configured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _setenv_required(monkeypatch)
    s = Settings()
    assert s.use_connect_api is False


def test_use_connect_api_true_when_both_set(monkeypatch: pytest.MonkeyPatch) -> None:
    _setenv_required(monkeypatch)
    monkeypatch.setenv("SO_CLIENT_ID", "client-abc")
    monkeypatch.setenv("SO_CLIENT_SECRET", "secret-xyz")
    s = Settings()
    assert s.use_connect_api is True


def test_use_connect_api_false_when_only_id_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _setenv_required(monkeypatch)
    monkeypatch.setenv("SO_CLIENT_ID", "client-abc")
    # Secret intentionally missing
    s = Settings()
    assert s.use_connect_api is False


def test_network_is_internal_v4(monkeypatch: pytest.MonkeyPatch) -> None:
    _setenv_required(monkeypatch)
    s = Settings()
    assert s.network_is_internal("10.5.5.5") is True
    assert s.network_is_internal("192.168.1.50") is True
    assert s.network_is_internal("8.8.8.8") is False
    assert s.network_is_internal("not-an-ip") is False


def test_network_is_internal_v6_falls_through(monkeypatch: pytest.MonkeyPatch) -> None:
    _setenv_required(monkeypatch)
    # Default config has only IPv4 CIDRs, so any IPv6 should be "external".
    s = Settings()
    assert s.network_is_internal("fe80::1") is False
    assert s.network_is_internal("::1") is False


def test_secret_str_redacts_in_repr(monkeypatch: pytest.MonkeyPatch) -> None:
    _setenv_required(monkeypatch)
    s = Settings()
    assert "password123" not in repr(s)
    assert "SecretStr" in repr(s.so_password)


def test_get_settings_caches(monkeypatch: pytest.MonkeyPatch) -> None:
    _setenv_required(monkeypatch)
    a = get_settings()
    b = get_settings()
    assert a is b


def test_so_ca_bundle_accepts_path(monkeypatch: pytest.MonkeyPatch) -> None:
    _setenv_required(monkeypatch)
    monkeypatch.setenv("SO_CA_BUNDLE", "/etc/pki/ca.pem")
    s = Settings()
    assert s.so_ca_bundle == Path("/etc/pki/ca.pem")


def test_blocklist_settings_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    """New blocklist + maxmind settings have sane defaults."""
    _setenv_required(monkeypatch)
    s = Settings()
    # Default is True once the evidence-aware validators cleared the
    # real-stratum agreement_rate gate under cross-validation.
    assert s.synth_first_pipeline is True
    assert s.blocklist_data_dir.name == "blocklists"
    assert s.maxmind_data_dir.name == "maxmind"
    assert s.blocklist_sources == ["urlhaus", "threatfox", "feodo", "tor", "internal_seed"]
    assert s.maxmind_license_key is None  # opt-in
    assert s.cloud_prefix_data_dir.name == "cloud_prefixes"
    assert s.blocklist_stale_threshold_days == 7
    assert s.spamhaus_license_acknowledged is False


def test_blocklist_sources_can_enable_spamhaus(monkeypatch: pytest.MonkeyPatch) -> None:
    """Spamhaus is opt-in and requires explicit license acknowledgement."""
    _setenv_required(monkeypatch)
    monkeypatch.setenv("BLOCKLIST_SOURCES", "urlhaus,spamhaus_drop")
    monkeypatch.setenv("SPAMHAUS_LICENSE_ACKNOWLEDGED", "true")
    s = Settings()
    assert "spamhaus_drop" in s.blocklist_sources
    assert s.spamhaus_license_acknowledged is True


def test_azure_service_tags_url_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """azure_service_tags_url has an explicit default (not magic) so overriding is obvious."""
    _setenv_required(monkeypatch)
    s = Settings()
    url_str = str(s.azure_service_tags_url)
    assert "ServiceTags_Public_" in url_str
    assert url_str.startswith("https://download.microsoft.com/")


def test_azure_service_tags_url_overridable(monkeypatch: pytest.MonkeyPatch) -> None:
    """Operator can point azure_service_tags_url at a newer snapshot via env."""
    _setenv_required(monkeypatch)
    monkeypatch.setenv(
        "AZURE_SERVICE_TAGS_URL",
        "https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/"
        "ServiceTags_Public_20261201.json",
    )
    s = Settings()
    assert "20261201" in str(s.azure_service_tags_url)


def test_cloud_prefix_stale_threshold_days_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """cloud_prefix_stale_threshold_days defaults to 45."""
    _setenv_required(monkeypatch)
    s = Settings()
    assert s.cloud_prefix_stale_threshold_days == 45


def test_webui_settings_defaults(settings_kratos: Settings) -> None:
    """Phase-1 web UI settings exist with safe defaults."""
    assert settings_kratos.soc_ai_data_dir == Path("data")
    # The fixture opts into dev-open mode; the production default is asserted in
    # test_api_auth_required_secure_default below.
    assert settings_kratos.api_auth_required is False
    assert settings_kratos.session_ttl_hours == 12
    assert settings_kratos.bootstrap_admin_password is None


def test_api_auth_required_secure_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Production default requires API auth (secure-by-default)."""
    _setenv_required(monkeypatch)
    assert Settings().api_auth_required is True


def test_events_index_pattern_single_node_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """Default index patterns target single-node SO 3.0 (logs-* data streams),
    not the legacy ``*:so-*`` form that matched the wrong index family."""
    _setenv_required(monkeypatch)
    s = Settings()
    assert s.events_index_pattern == "logs-*"
    assert s.cases_index_pattern == "so-case*"
    assert s.detections_index_pattern == "so-detection*"
    assert s.playbooks_index_pattern == "so-playbook*"


def test_webui_alerts_query_default(settings_kratos: Settings) -> None:
    assert settings_kratos.webui_alerts_query == "tags:alert"


def test_inherit_window_default(settings_kratos: Settings) -> None:
    assert settings_kratos.webui_inherit_window_days == 7


# ---------------------------------------------------------------------------
# Timeout / wall-clock backstop knobs
# ---------------------------------------------------------------------------


def test_timeout_knob_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    """The chat/hunt/investigation wall-clock backstops carry the intended
    defaults, and the hunt tier is slower than the investigation-chat tier."""
    _setenv_required(monkeypatch)
    s = Settings()
    assert s.chat_turn_timeout_s == 300
    assert s.hunt_chat_turn_timeout_s == 600
    assert s.hunt_run_timeout_s == 1800
    assert s.investigation_run_timeout_s == 900
    assert s.investigation_turn_timeout_s == 600
    # A hunt-chat turn is granted more wall-clock than an investigation chat turn.
    assert s.hunt_chat_turn_timeout_s > s.chat_turn_timeout_s
    # The whole-hunt safety net outlasts a single hunt-chat turn.
    assert s.hunt_run_timeout_s > s.hunt_chat_turn_timeout_s
    # The per-turn backstop is a true backstop: larger than a single gateway
    # request timeout so it doesn't cut a turn that is legitimately retrying.
    assert s.investigation_turn_timeout_s > s.litellm_request_timeout_s


def test_timeout_knobs_overridable_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each timeout knob is env-overridable (case-insensitive keys)."""
    _setenv_required(monkeypatch)
    monkeypatch.setenv("HUNT_CHAT_TURN_TIMEOUT_S", "720")
    monkeypatch.setenv("HUNT_RUN_TIMEOUT_S", "2400")
    monkeypatch.setenv("INVESTIGATION_RUN_TIMEOUT_S", "1200")
    monkeypatch.setenv("INVESTIGATION_TURN_TIMEOUT_S", "420")
    s = Settings()
    assert s.hunt_chat_turn_timeout_s == 720
    assert s.hunt_run_timeout_s == 2400
    assert s.investigation_run_timeout_s == 1200
    assert s.investigation_turn_timeout_s == 420


# ---------------------------------------------------------------------------
# Auto-ack false-positive settings
# ---------------------------------------------------------------------------


def test_auto_ack_fp_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    """auto_ack_fp_enabled defaults to False, threshold to 0.7."""
    _setenv_required(monkeypatch)
    s = Settings()
    assert s.auto_ack_fp_enabled is False
    assert s.auto_ack_fp_threshold == 0.7


def test_auto_ack_fp_threshold_valid_range(monkeypatch: pytest.MonkeyPatch) -> None:
    """Threshold accepts any float in [0.0, 1.0]."""
    _setenv_required(monkeypatch)
    monkeypatch.setenv("AUTO_ACK_FP_THRESHOLD", "0.9")
    s = Settings()
    assert s.auto_ack_fp_threshold == 0.9


def test_auto_ack_fp_threshold_rejects_below_zero(monkeypatch: pytest.MonkeyPatch) -> None:
    """Threshold below 0.0 is rejected with ValidationError."""
    _setenv_required(monkeypatch)
    monkeypatch.setenv("AUTO_ACK_FP_THRESHOLD", "-0.1")
    with pytest.raises(ValidationError):
        Settings()


def test_auto_ack_fp_threshold_rejects_above_one(monkeypatch: pytest.MonkeyPatch) -> None:
    """Threshold above 1.0 is rejected with ValidationError."""
    _setenv_required(monkeypatch)
    monkeypatch.setenv("AUTO_ACK_FP_THRESHOLD", "1.5")
    with pytest.raises(ValidationError):
        Settings()


def test_auto_ack_fp_threshold_boundary_values(monkeypatch: pytest.MonkeyPatch) -> None:
    """Boundary values 0.0 and 1.0 are both accepted."""
    _setenv_required(monkeypatch)
    monkeypatch.setenv("AUTO_ACK_FP_THRESHOLD", "0.0")
    assert Settings().auto_ack_fp_threshold == 0.0
    monkeypatch.setenv("AUTO_ACK_FP_THRESHOLD", "1.0")
    assert Settings().auto_ack_fp_threshold == 1.0


# ---------------------------------------------------------------------------
# Auto-triage minimum severity settings
# ---------------------------------------------------------------------------


def test_auto_triage_min_severity_default(monkeypatch: pytest.MonkeyPatch) -> None:
    """auto_triage_min_severity defaults to 'high'."""
    _setenv_required(monkeypatch)
    s = Settings()
    assert s.auto_triage_min_severity == "high"


def test_auto_triage_min_severity_accepts_all_valid(monkeypatch: pytest.MonkeyPatch) -> None:
    """All valid severity names are accepted and lowercased."""
    _setenv_required(monkeypatch)
    for sev in ("critical", "high", "medium", "low"):
        monkeypatch.setenv("AUTO_TRIAGE_MIN_SEVERITY", sev)
        assert Settings().auto_triage_min_severity == sev


def test_auto_triage_min_severity_lowercases(monkeypatch: pytest.MonkeyPatch) -> None:
    """CRITICAL (uppercase) is accepted and normalised to lowercase."""
    _setenv_required(monkeypatch)
    monkeypatch.setenv("AUTO_TRIAGE_MIN_SEVERITY", "CRITICAL")
    assert Settings().auto_triage_min_severity == "critical"


def test_auto_triage_min_severity_rejects_invalid(monkeypatch: pytest.MonkeyPatch) -> None:
    """Unknown severity names are rejected with ValidationError."""
    _setenv_required(monkeypatch)
    monkeypatch.setenv("AUTO_TRIAGE_MIN_SEVERITY", "bogus")
    with pytest.raises(ValidationError):
        Settings()


# ---------------------------------------------------------------------------
# Admin config-console whitelist integrity (inc 1: env-only settings surfaced)
# ---------------------------------------------------------------------------

# Settings reserved for the internal-identifier discovery managed-list UI
# (increments 2/3) — these must NOT be surfaced as plain config rows now.
_RESERVED_INTERNAL_IDENTIFIER_KEYS = frozenset(
    {"internal_cidrs", "oracle_internal_suffixes", "oracle_extra_hosts"}
)

# Settings newly surfaced in increment 1 (env-only → editable in the pane).
_INC1_SURFACED = frozenset(
    {
        "events_index_pattern",
        "cases_index_pattern",
        "detections_index_pattern",
        "playbooks_index_pattern",
        "webui_alerts_query",
        "webui_inherit_window_days",
        "synth_first_pipeline",
        "enable_rule_class_fast_path",
        "synthesis_confidence_floor",
        "fast_path_synthesis_floor",
        "fast_path_sampling_rate",
        "investigator_max_response_tokens",
    }
)


def test_inc1_settings_are_whitelisted() -> None:
    """Every increment-1 setting is registered in the admin whitelist."""
    from soc_ai.store.config_overrides import WHITELIST_BY_KEY

    missing = _INC1_SURFACED - set(WHITELIST_BY_KEY)
    assert not missing, f"inc1 settings not whitelisted: {sorted(missing)}"


def test_whitelist_attrs_all_exist_on_settings() -> None:
    """Every whitelisted spec maps to a real, declared Settings attribute."""
    from soc_ai.store.config_overrides import WHITELIST

    fields = set(Settings.model_fields)
    for spec in WHITELIST:
        assert spec.attr in fields, f"{spec.attr} is not a Settings field"


def test_no_reserved_or_secret_in_rendered_groups() -> None:
    """The rendered settings groups never expose a reserved internal-id or a secret.

    Secrets live either in the Danger Zone (connection identity) or the dedicated
    write-only "API keys" section. Neither section is in SECTION_ORDER, so the
    GET /config groups endpoint can't render — let alone leak — a secret value.
    """
    from soc_ai.store.config_overrides import SECTION_ORDER, WHITELIST

    for spec in WHITELIST:
        if spec.danger:
            continue  # Danger Zone handles connection identity + secrets
        if spec.secret:
            # The only non-danger home for a secret is the API-keys panel, and
            # that section must NOT be one the groups endpoint renders.
            assert spec.section == "API keys", (
                f"{spec.key} is a secret in section {spec.section!r}; a secret belongs in "
                "the Danger Zone or the dedicated 'API keys' section"
            )
            assert spec.section not in SECTION_ORDER, (
                f"section {spec.section!r} is rendered by GET /config — it must not hold secrets"
            )
        assert spec.key not in _RESERVED_INTERNAL_IDENTIFIER_KEYS, (
            f"{spec.key} is reserved for the inc 2/3 managed-list UI"
        )


def test_inc1_sections_are_in_display_order() -> None:
    """Sections used by inc1 settings appear in SECTION_ORDER, so GET /config
    actually serializes them (the endpoint iterates SECTION_ORDER)."""
    from soc_ai.store.config_overrides import SECTION_ORDER, WHITELIST_BY_KEY

    for key in _INC1_SURFACED:
        section = WHITELIST_BY_KEY[key].section
        assert section in SECTION_ORDER, f"{section!r} (for {key}) missing from SECTION_ORDER"


def test_inc1_settings_coerce_from_form_strings() -> None:
    """Each inc1 setting coerces a representative raw form string to its type."""
    from soc_ai.store import config_overrides as cfg

    samples: dict[str, tuple[str, object]] = {
        "events_index_pattern": ("logs-*", "logs-*"),
        "webui_alerts_query": ("event.dataset:suricata.alert", "event.dataset:suricata.alert"),
        "webui_inherit_window_days": ("14", 14),
        "synth_first_pipeline": ("true", True),
        "enable_rule_class_fast_path": ("", False),  # unchecked checkbox → False
        "fast_path_synthesis_floor": ("0.4", 0.4),
        "investigator_max_response_tokens": ("16000", 16000),
    }
    for key, (raw, expected) in samples.items():
        assert cfg.coerce(key, raw) == expected


def test_url_setting_rejects_non_http_scheme() -> None:
    """S11: URL settings allow any host (admin intent) but reject non-http(s)
    schemes (file://, gopher:// — SSRF vectors)."""
    from soc_ai.store.config_overrides import coerce

    with pytest.raises(ValueError):
        coerce("searxng_url", "file:///etc/passwd")
    with pytest.raises(ValueError):
        coerce("crawl4ai_url", "gopher://attacker/x")
    # Any host is allowed — an admin may legitimately use an internal service.
    assert coerce("searxng_url", "http://127.0.0.1:8888") == "http://127.0.0.1:8888"
    assert (
        coerce("crawl4ai_url", "https://crawl.internal.example") == "https://crawl.internal.example"
    )
    assert coerce("searxng_url", "") == ""  # unset is fine


def test_fast_triage_toggle_default_and_whitelisted(monkeypatch: pytest.MonkeyPatch) -> None:
    """F2: the fast-triage toggle defaults on (current behavior) and is exposed
    in the admin config console with the speed/depth tradeoff note."""
    from soc_ai.store.config_overrides import WHITELIST_BY_KEY

    _setenv_required(monkeypatch)
    assert Settings().fast_triage_enabled is True
    spec = WHITELIST_BY_KEY["fast_triage_enabled"]
    assert spec.type == "bool"
    assert "shallower" in spec.help.lower()


def test_csv_env_forms_for_oracle_and_proxy_lists(monkeypatch: pytest.MonkeyPatch) -> None:
    """Regression: the documented comma-separated env forms for the Oracle
    privacy-gate lists and proxy_trusted_ips must load, not crash Settings.

    Without a ``NoDecode`` annotation, pydantic-settings JSON-decodes a
    complex-typed env value BEFORE the before-validators run, so a bare CSV like
    ``.lan,.local`` raised SettingsError at import/startup — making the app fail
    to boot when the operator followed the docstring.
    """
    _setenv_required(monkeypatch)
    monkeypatch.setenv("ORACLE_INTERNAL_SUFFIXES", ".lan,.local,.myco.internal")
    monkeypatch.setenv("ORACLE_EXTRA_HOSTS", "WIN11-01,APPSERVER01,dbserver")
    monkeypatch.setenv("PROXY_TRUSTED_IPS", "192.0.2.1,192.0.2.2")
    s = Settings()
    assert s.oracle_internal_suffixes == (".lan", ".local", ".myco.internal")
    assert s.oracle_extra_hosts == ["WIN11-01", "APPSERVER01", "dbserver"]
    assert s.proxy_trusted_ips == ["192.0.2.1", "192.0.2.2"]
    # A single bare value must also work (not just multi-item CSV).
    monkeypatch.setenv("PROXY_TRUSTED_IPS", "192.0.2.1")
    assert Settings().proxy_trusted_ips == ["192.0.2.1"]


def test_apply_to_settings_returns_only_applied_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    """apply_to_settings reports which overrides actually took.

    A value that is type-correct but rejected by a field validator at assignment
    time is skipped silently (so a bad DB override never crashes startup). The
    return value lets POST /config/setting tell that silent skip from success and
    roll back instead of reporting ok on a value that never applied. Regression
    for FR-072.
    """
    from soc_ai.store.config_overrides import apply_to_settings

    _setenv_required(monkeypatch)
    s = Settings()
    applied = apply_to_settings(
        s,
        {
            "oracle_enabled": True,  # valid → applied
            "auto_ack_fp_threshold": 5.0,  # out of [0,1] → field validator rejects → skipped
        },
    )
    assert "oracle_enabled" in applied
    assert "auto_ack_fp_threshold" not in applied
    assert s.oracle_enabled is True


# ---------------------------------------------------------------------------
# Self-consistency vote flag — verdict_consistency_samples
# ---------------------------------------------------------------------------


def test_verdict_consistency_samples_default_is_one(monkeypatch: pytest.MonkeyPatch) -> None:
    """The vote ships OFF: samples=1 ⇒ single synthesis call, no vote,
    `inconclusive` never produced (byte-identical default behavior)."""
    _setenv_required(monkeypatch)
    assert Settings().verdict_consistency_samples == 1


def test_verdict_consistency_samples_valid_override(monkeypatch: pytest.MonkeyPatch) -> None:
    _setenv_required(monkeypatch)
    monkeypatch.setenv("VERDICT_CONSISTENCY_SAMPLES", "3")
    assert Settings().verdict_consistency_samples == 3
    monkeypatch.setenv("VERDICT_CONSISTENCY_SAMPLES", "5")
    assert Settings().verdict_consistency_samples == 5


@pytest.mark.parametrize("bad", ["0", "6", "-1", "100"])
def test_verdict_consistency_samples_out_of_range_raises(
    monkeypatch: pytest.MonkeyPatch, bad: str
) -> None:
    _setenv_required(monkeypatch)
    monkeypatch.setenv("VERDICT_CONSISTENCY_SAMPLES", bad)
    with pytest.raises(ValidationError) as excinfo:
        Settings()
    assert "verdict_consistency_samples" in str(excinfo.value)


def test_verdict_consistency_samples_junk_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    _setenv_required(monkeypatch)
    monkeypatch.setenv("VERDICT_CONSISTENCY_SAMPLES", "three")
    with pytest.raises(ValidationError):
        Settings()


def test_verdict_consistency_samples_is_hot_whitelisted() -> None:
    """The config console can hot-apply the flag (int, bounded 1..5)."""
    from soc_ai.store.config_overrides import WHITELIST_BY_KEY

    spec = WHITELIST_BY_KEY["verdict_consistency_samples"]
    assert spec.hot is True
    assert spec.type == "int"
    assert spec.min_value == 1
    assert spec.max_value == 5
    assert spec.secret is False
    assert spec.danger is False
