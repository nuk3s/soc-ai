"""Tests for :mod:`soc_ai.agent.classifier` (issue #18)."""

from __future__ import annotations

from soc_ai.agent.classifier import AlertClass, classify_alert, is_fast_path_eligible
from soc_ai.so_client.models import RuleMetadata, SoAlert


def test_classify_uses_classtype_first() -> None:
    """Classtype is the strongest signal — it's rule-author-declared."""
    alert = SoAlert(
        id="a1",
        classtype="trojan-activity",
        rule_metadata=RuleMetadata(signature_severity="Informational"),
    )
    # Classtype trumps signature_severity even when they disagree.
    assert classify_alert(alert) is AlertClass.POST_COMPROMISE


def test_classify_misc_activity_is_informational() -> None:
    alert = SoAlert(id="a", classtype="misc-activity")
    assert classify_alert(alert) is AlertClass.INFORMATIONAL_VISIBILITY


def test_classify_attempted_recon_is_recon() -> None:
    alert = SoAlert(id="a", classtype="attempted-recon")
    assert classify_alert(alert) is AlertClass.RECON


def test_classify_web_app_attack_is_exploit() -> None:
    alert = SoAlert(id="a", classtype="web-application-attack")
    assert classify_alert(alert) is AlertClass.EXPLOIT_ATTEMPT


def test_classify_command_and_control_is_post_compromise() -> None:
    alert = SoAlert(id="a", classtype="command-and-control")
    assert classify_alert(alert) is AlertClass.POST_COMPROMISE


def test_classify_falls_back_to_signature_severity() -> None:
    """When no classtype is present, signature_severity drives the bucket."""
    informational = SoAlert(id="a", rule_metadata=RuleMetadata(signature_severity="Informational"))
    assert classify_alert(informational) is AlertClass.INFORMATIONAL_VISIBILITY

    major = SoAlert(id="a", rule_metadata=RuleMetadata(signature_severity="Major"))
    assert classify_alert(major) is AlertClass.EXPLOIT_ATTEMPT

    critical = SoAlert(id="a", rule_metadata=RuleMetadata(signature_severity="Critical"))
    assert classify_alert(critical) is AlertClass.POST_COMPROMISE


def test_classify_unknown_when_no_signal() -> None:
    """No classtype, no rule_metadata → UNKNOWN (full pipeline)."""
    alert = SoAlert(id="a")
    assert classify_alert(alert) is AlertClass.UNKNOWN


def test_classify_does_not_use_rule_name() -> None:
    """Mitigation: classifier never reads rule_name strings (closed allowlist
    on metadata, not regex on names)."""
    # An alert with a misleading "ET INFO" rule name but a malicious classtype
    # must classify as POST_COMPROMISE — never fall back to the name prefix.
    alert = SoAlert(
        id="a",
        rule_name="ET INFO This Looks Benign But Isn't",
        classtype="trojan-activity",
    )
    assert classify_alert(alert) is AlertClass.POST_COMPROMISE


def test_fast_path_eligible_only_for_informational_low() -> None:
    informational_low = SoAlert(
        id="a",
        severity_label="low",
        rule_metadata=RuleMetadata(signature_severity="Informational"),
    )
    cls = classify_alert(informational_low)
    assert is_fast_path_eligible(informational_low, cls) is True


def test_fast_path_not_eligible_for_informational_high() -> None:
    """Even for an Informational signature, severity=high (operator-bumped)
    means the SO operator wants the full pipeline."""
    informational_high = SoAlert(
        id="a",
        severity_label="high",
        rule_metadata=RuleMetadata(signature_severity="Informational"),
    )
    cls = classify_alert(informational_high)
    assert is_fast_path_eligible(informational_high, cls) is False


def test_fast_path_not_eligible_for_recon_low() -> None:
    """Recon class never takes the fast path even at severity=low."""
    recon = SoAlert(id="a", severity_label="low", classtype="attempted-recon")
    cls = classify_alert(recon)
    assert is_fast_path_eligible(recon, cls) is False


def test_fast_path_not_eligible_for_post_compromise() -> None:
    """Post-compromise class never takes the fast path."""
    pc = SoAlert(id="a", severity_label="low", classtype="trojan-activity")
    cls = classify_alert(pc)
    assert is_fast_path_eligible(pc, cls) is False


def test_classify_severity_case_insensitive() -> None:
    """Suricata sometimes lowercases the severity label; the classifier
    must not be case-sensitive."""
    alert = SoAlert(id="a", rule_metadata=RuleMetadata(signature_severity="INFORMATIONAL"))
    assert classify_alert(alert) is AlertClass.INFORMATIONAL_VISIBILITY


# --- Domain-reputation fast-path gate ---------------------------------------


class _StubCache:
    """Minimal enrichment-cache stand-in exposing the ``contains`` probe."""

    def __init__(self, seen: set[str] | None = None) -> None:
        self._seen = seen or set()

    def contains(self, key: str) -> bool:
        return key in self._seen


class _StubBlocklist:
    """Minimal blocklist stand-in exposing ``lookup_domain``."""

    def __init__(self, malicious: set[str] | None = None) -> None:
        self._malicious = malicious or set()

    def lookup_domain(self, domain: str) -> list[object]:
        return ["hit"] if domain.lower() in self._malicious else []


def _informational_low(**extra: object) -> SoAlert:
    return SoAlert(
        id="a",
        severity_label="low",
        rule_metadata=RuleMetadata(signature_severity="Informational"),
        **extra,  # type: ignore[arg-type]
    )


def test_fast_path_external_domain_without_reputation_not_eligible() -> None:
    """An external destination *domain* with no prior reputation context
    (no blocklist hit, never enriched) must NOT fast-path — it routes to
    the full pipeline once, mirroring the first-encounter external-IP gate."""
    alert = _informational_low(zeek_ssl_server_name="newly-registered.example")
    cls = classify_alert(alert)
    assert (
        is_fast_path_eligible(
            alert,
            cls,
            enrichment_cache=_StubCache(),
            blocklist=_StubBlocklist(),
        )
        is False
    )


def test_fast_path_external_domain_with_malicious_signal_not_eligible() -> None:
    """A domain with a malicious blocklist hit is never fast-pathed, even
    if it was previously enriched."""
    alert = _informational_low(zeek_http_host="evil.example")
    cls = classify_alert(alert)
    assert (
        is_fast_path_eligible(
            alert,
            cls,
            enrichment_cache=_StubCache(seen={"evil.example"}),
            blocklist=_StubBlocklist(malicious={"evil.example"}),
        )
        is False
    )


def test_fast_path_external_domain_with_port_still_matches_blocklist() -> None:
    """An HTTP Host carrying a ``:port`` suffix must be port-stripped before the
    blocklist lookup — "evil.example:443" has to match the "evil.example" entry,
    otherwise a known-bad domain wrongly fast-paths past the reputation gate."""
    alert = _informational_low(zeek_http_host="evil.example:443")
    cls = classify_alert(alert)
    assert (
        is_fast_path_eligible(
            alert,
            cls,
            enrichment_cache=_StubCache(seen={"evil.example"}),
            blocklist=_StubBlocklist(malicious={"evil.example"}),
        )
        is False
    )


def test_fast_path_external_domain_with_prior_enrichment_eligible() -> None:
    """A benign domain we've already enriched (cache hit, no blocklist hit)
    is eligible — the name-based mirror of a cached external IP."""
    alert = _informational_low(zeek_dns_query="known-good.example")
    cls = classify_alert(alert)
    assert (
        is_fast_path_eligible(
            alert,
            cls,
            enrichment_cache=_StubCache(seen={"known-good.example"}),
            blocklist=_StubBlocklist(),
        )
        is True
    )


def test_fast_path_domain_gate_inactive_without_blocklist_or_cache() -> None:
    """When neither blocklist nor cache is supplied, the domain gate is a
    no-op and legacy (IP-only) behavior stands — a domain-only alert is
    still eligible."""
    alert = _informational_low(zeek_ssl_server_name="anything.example")
    cls = classify_alert(alert)
    assert is_fast_path_eligible(alert, cls) is True


def test_fast_path_external_ip_with_cache_still_eligible_unchanged() -> None:
    """Regression guard: the external-IP path is unchanged. An external IP
    with a prior cache hit remains fast-path eligible, and passing a
    blocklist does not affect an IP-destination alert."""
    alert = _informational_low(destination_ip="8.8.8.8")
    cls = classify_alert(alert)
    assert (
        is_fast_path_eligible(
            alert,
            cls,
            enrichment_cache=_StubCache(seen={"8.8.8.8"}),
            blocklist=_StubBlocklist(),
        )
        is True
    )


def test_fast_path_external_ip_without_cache_not_eligible_unchanged() -> None:
    """Regression guard: a first-encounter external IP (no cache hit) is
    still rejected — the domain gate additions do not regress this."""
    alert = _informational_low(destination_ip="8.8.8.8")
    cls = classify_alert(alert)
    assert (
        is_fast_path_eligible(
            alert,
            cls,
            enrichment_cache=_StubCache(),
            blocklist=_StubBlocklist(),
        )
        is False
    )


def test_fast_path_ip_literal_in_domain_field_not_treated_as_domain() -> None:
    """An IP literal that lands in a name field (e.g. SNI) is not a domain;
    the domain gate skips it and the alert stays eligible (no IP dest set)."""
    alert = _informational_low(zeek_ssl_server_name="203.0.113.9")
    cls = classify_alert(alert)
    assert (
        is_fast_path_eligible(
            alert,
            cls,
            enrichment_cache=_StubCache(),
            blocklist=_StubBlocklist(),
        )
        is True
    )
