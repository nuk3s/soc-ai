"""Exhaustive tests for the Oracle privacy gate (soc_ai.oracle.sanitize).

This is the privacy boundary — every category must have positive (redacted),
negative (passes through), stability, reversibility, recursive, residue, and
allowlist coverage.
"""

from __future__ import annotations

import json

import pytest
from soc_ai.oracle.sanitize import (
    Mapping,
    desanitize,
    redaction_summary,
    sanitize,
    unsafe_residue,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _clean_mapping() -> Mapping:
    return Mapping()


# ---------------------------------------------------------------------------
# 1. Private IPv4 → tokenized; public IPv4 → PASS
# ---------------------------------------------------------------------------


class TestPrivateIPv4:
    def test_rfc1918_10_block(self) -> None:
        m = _clean_mapping()
        out = sanitize("conn from 10.0.0.5 to dst", m)
        assert isinstance(out, str)
        assert "10.0.0.5" not in out
        assert "IP_" in out

    def test_rfc1918_192_168(self) -> None:
        m = _clean_mapping()
        out = sanitize("src 192.168.1.100", m)
        assert "192.168.1.100" not in out

    def test_rfc1918_172_16(self) -> None:
        m = _clean_mapping()
        out = sanitize("host 172.16.254.1", m)
        assert "172.16.254.1" not in out

    def test_cgnat(self) -> None:
        m = _clean_mapping()
        out = sanitize("carrier 100.64.0.1", m)
        assert "100.64.0.1" not in out

    def test_loopback(self) -> None:
        m = _clean_mapping()
        out = sanitize("loopback 127.0.0.1 bound", m)
        assert "127.0.0.1" not in out

    def test_public_ipv4_passes_through(self) -> None:
        m = _clean_mapping()
        out = sanitize("dns 8.8.8.8 and 1.1.1.1 reached", m)
        assert "8.8.8.8" in out
        assert "1.1.1.1" in out
        assert m.counters.get("IP", 0) == 0

    def test_multiple_private_ips_distinct_labels(self) -> None:
        m = _clean_mapping()
        out = sanitize("10.0.0.1 and 192.168.0.1", m)
        assert m.counters.get("IP", 0) == 2
        assert "10.0.0.1" not in out
        assert "192.168.0.1" not in out


# ---------------------------------------------------------------------------
# 2. Private IPv6 → tokenized; public IPv6 → PASS
# ---------------------------------------------------------------------------


class TestPrivateIPv6:
    def test_ula_prefix(self) -> None:
        m = _clean_mapping()
        out = sanitize("addr fd00::1 seen", m)
        assert "fd00::1" not in out
        assert "IP_" in out

    def test_link_local(self) -> None:
        m = _clean_mapping()
        out = sanitize("iface fe80::1", m)
        assert "fe80::1" not in out

    def test_loopback_v6(self) -> None:
        m = _clean_mapping()
        out = sanitize("loopback ::1 present", m)
        assert " ::1 " not in f" {out} "

    def test_public_ipv6_passes(self) -> None:
        m = _clean_mapping()
        addr = "2606:4700::1"
        out = sanitize(f"cf {addr}", m)
        assert addr in out
        assert m.counters.get("IP", 0) == 0

    def test_mixed_public_private(self) -> None:
        m = _clean_mapping()
        # 2606:4700::1 is Cloudflare (public); fe80::abcd is link-local (private)
        out = sanitize("pub 2606:4700::1 priv fe80::abcd", m)
        assert "2606:4700::1" in out  # public — preserved
        assert "fe80::abcd" not in out


# ---------------------------------------------------------------------------
# 3. Internal hostnames → tokenized; public domains → PASS
# ---------------------------------------------------------------------------


class TestHostnames:
    def test_fqdn_lan_suffix(self) -> None:
        m = _clean_mapping()
        out = sanitize("dc01.lan connected", m)
        assert "dc01.lan" not in out
        assert "HOST_" in out

    def test_fqdn_local_suffix(self) -> None:
        m = _clean_mapping()
        out = sanitize("server.local queried", m)
        assert "server.local" not in out

    def test_fqdn_internal_suffix(self) -> None:
        m = _clean_mapping()
        out = sanitize("svc.internal responded", m)
        assert "svc.internal" not in out

    def test_fqdn_corp_suffix(self) -> None:
        m = _clean_mapping()
        # .corp is a suffix so anything ending in .corp is internal
        out2 = sanitize("host.corp hit", m)
        assert "host.corp" not in out2

    def test_public_domain_passes(self) -> None:
        m = _clean_mapping()
        out = sanitize("evil.com microsoft.com victim went to google.com", m)
        assert "evil.com" in out
        assert "microsoft.com" in out
        assert "google.com" in out

    def test_extra_hosts_via_param(self) -> None:
        m = _clean_mapping()
        out = sanitize("appserver queried", m, extra_hosts=["appserver"])
        assert "appserver" not in out

    def test_extra_suffix_via_param(self) -> None:
        m = _clean_mapping()
        out = sanitize("svc.myco.example", m, extra_suffixes=[".myco.example"])
        assert "svc.myco.example" not in out

    def test_public_domain_suffix_not_partial_matched(self) -> None:
        """evil.local-ai.com must NOT be partially redacted."""
        m = _clean_mapping()
        out = sanitize("url evil.local-ai.com", m)
        # The whole token should still be present (it's not a .local FQDN)
        assert "evil.local-ai.com" in out

    def test_public_domain_with_internal_label_midstring_not_corrupted(self) -> None:
        """A PUBLIC domain whose mid-FQDN label equals an internal suffix word
        (``x.local.evil.com``) must pass through verbatim, NOT be tokenized to
        ``HOST_NN.evil.com``.  The suffix should only match at the true end of
        an FQDN, not in the middle.  (Over-redaction corrupts the IOC the
        Oracle needs to reason about — a correctness/data-integrity defect.)"""
        m = _clean_mapping()
        out = sanitize("c2 callback to x.local.evil.com and foo.internal.evil.com", m)
        assert "x.local.evil.com" in out
        assert "foo.internal.evil.com" in out
        assert "HOST_" not in out


# ---------------------------------------------------------------------------
# 4. Internal emails → tokenized; public emails → PASS
# ---------------------------------------------------------------------------


class TestEmails:
    def test_internal_email_redacted(self) -> None:
        m = _clean_mapping()
        out = sanitize("alert from bob@corp.lan cc admin@internal", m)
        assert "bob@corp.lan" not in out
        assert "EMAIL_" in out

    def test_public_email_passes(self) -> None:
        m = _clean_mapping()
        out = sanitize("reporter abuse@anthropic.com", m)
        assert "abuse@anthropic.com" in out
        assert m.counters.get("EMAIL", 0) == 0

    def test_internal_email_corp_suffix(self) -> None:
        m = _clean_mapping()
        out = sanitize("user user@internal.corp", m)
        assert "user@internal.corp" not in out


# ---------------------------------------------------------------------------
# 5. /home/<user>/ → username tokenized, path tail preserved
# ---------------------------------------------------------------------------


class TestHomePaths:
    def test_username_redacted_tail_preserved(self) -> None:
        m = _clean_mapping()
        out = sanitize("opened /home/analyst/keys/id_rsa", m)
        assert "analyst" not in out
        assert "/home/USER_" in out
        assert "/keys/id_rsa" in out

    def test_different_user_different_label(self) -> None:
        m = _clean_mapping()
        out = sanitize("/home/alice/x and /home/bob/y", m)
        assert "alice" not in out
        assert "bob" not in out
        # Two distinct users → two distinct USER labels
        assert m.counters.get("USER", 0) == 2


# ---------------------------------------------------------------------------
# 6. MAC addresses → always tokenized
# ---------------------------------------------------------------------------


class TestMac:
    def test_colon_mac(self) -> None:
        m = _clean_mapping()
        out = sanitize("aa:bb:cc:dd:ee:ff seen", m)
        assert "aa:bb:cc:dd:ee:ff" not in out
        assert "MAC_" in out

    def test_hyphen_mac(self) -> None:
        m = _clean_mapping()
        out = sanitize("00-11-22-33-44-55 source", m)
        assert "00-11-22-33-44-55" not in out

    def test_two_macs_distinct_labels(self) -> None:
        m = _clean_mapping()
        out = sanitize("aa:bb:cc:dd:ee:ff and 00:11:22:33:44:55", m)
        assert m.counters.get("MAC", 0) == 2
        assert "aa:bb:cc:dd:ee:ff" not in out


# ---------------------------------------------------------------------------
# 7. PASS-THROUGH set — these must NEVER be redacted
# ---------------------------------------------------------------------------


class TestPassThrough:
    PAYLOAD = (
        "Public IP 8.8.8.8 resolved evil.com https://evil.com/x.exe "
        "hash e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855 "
        "CVE-2024-1234 T1055 port 443 rule ET.MALWARE.BPFDoor "
        "bytes \\x90\\x90\\x90 "
        "sha1 da39a3ee5e6b4b0d3255bfef95601890afd80709"
    )

    def test_public_ip_untouched(self) -> None:
        m = _clean_mapping()
        out = sanitize(self.PAYLOAD, m)
        assert "8.8.8.8" in out

    def test_public_domain_untouched(self) -> None:
        m = _clean_mapping()
        out = sanitize(self.PAYLOAD, m)
        assert "evil.com" in out

    def test_url_untouched(self) -> None:
        m = _clean_mapping()
        out = sanitize(self.PAYLOAD, m)
        assert "https://evil.com/x.exe" in out

    def test_sha256_untouched(self) -> None:
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        m = _clean_mapping()
        out = sanitize(self.PAYLOAD, m)
        assert sha256 in out

    def test_cve_untouched(self) -> None:
        m = _clean_mapping()
        out = sanitize(self.PAYLOAD, m)
        assert "CVE-2024-1234" in out

    def test_attck_technique_untouched(self) -> None:
        m = _clean_mapping()
        out = sanitize(self.PAYLOAD, m)
        assert "T1055" in out

    def test_port_untouched(self) -> None:
        m = _clean_mapping()
        out = sanitize(self.PAYLOAD, m)
        assert "443" in out

    def test_rule_name_untouched(self) -> None:
        m = _clean_mapping()
        out = sanitize(self.PAYLOAD, m)
        assert "ET.MALWARE.BPFDoor" in out

    def test_payload_bytes_untouched(self) -> None:
        m = _clean_mapping()
        out = sanitize(self.PAYLOAD, m)
        assert "\\x90\\x90\\x90" in out

    def test_sha1_untouched(self) -> None:
        sha1 = "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        m = _clean_mapping()
        out = sanitize(self.PAYLOAD, m)
        assert sha1 in out


# ---------------------------------------------------------------------------
# 8. Stability — same value → same label; different values → different labels
# ---------------------------------------------------------------------------


class TestStability:
    def test_same_ip_same_label(self) -> None:
        m = _clean_mapping()
        out1 = sanitize("first 10.0.0.1", m)
        out2 = sanitize("second 10.0.0.1", m)
        label1 = out1.split()[-1]
        label2 = out2.split()[-1]
        assert label1 == label2

    def test_two_ips_different_labels(self) -> None:
        m = _clean_mapping()
        out = sanitize("a 10.0.0.1 b 10.0.0.2", m)
        labels = [tok for tok in out.split() if tok.startswith("IP_")]
        assert len(labels) == 2
        assert labels[0] != labels[1]

    def test_reuse_across_calls(self) -> None:
        m = _clean_mapping()
        out1 = sanitize("src 10.1.2.3", m)
        out2 = sanitize("src again 10.1.2.3", m)
        lbl = m.forward["10.1.2.3"]
        assert lbl in out1
        assert lbl in out2
        # Counter stays at 1 (no double allocation)
        assert m.counters["IP"] == 1


# ---------------------------------------------------------------------------
# 9. Reversibility — desanitize(sanitize(x)) == x
# ---------------------------------------------------------------------------


class TestReversibility:
    def test_roundtrip_str(self) -> None:
        original = "alert from 10.20.30.148 to dc01.lan via aa:bb:cc:dd:ee:ff"
        m = _clean_mapping()
        out = sanitize(original, m)
        restored = desanitize(out, m)
        assert restored == original

    def test_roundtrip_dict(self) -> None:
        original = {"src": "10.0.0.1", "dst": "8.8.8.8", "host": "server.local"}
        m = _clean_mapping()
        out = sanitize(original, m)
        restored = desanitize(out, m)
        assert restored == original

    def test_roundtrip_nested(self) -> None:
        original = {
            "alert": {"src_ip": "192.168.1.1", "payload": "bytes 00:11:22:33:44:55"},
            "tags": ["10.0.0.1", "evil.com"],
        }
        m = _clean_mapping()
        out = sanitize(original, m)
        restored = desanitize(out, m)
        assert restored == original

    def test_desanitize_str(self) -> None:
        m = _clean_mapping()
        sanitized = sanitize("10.0.0.1 8.8.8.8", m)
        assert isinstance(sanitized, str)
        assert desanitize(sanitized, m) == "10.0.0.1 8.8.8.8"


# ---------------------------------------------------------------------------
# 10. Recursive — nested dict/list/tuple with internal values in keys + values
# ---------------------------------------------------------------------------


class TestRecursive:
    def test_dict_key_sanitized(self) -> None:
        m = _clean_mapping()
        # A dict key that is an internal IP should be redacted
        d: dict[str, str] = {"10.0.0.1": "src"}
        out = sanitize(d, m)
        assert isinstance(out, dict)
        assert "10.0.0.1" not in out
        keys = list(out.keys())
        assert len(keys) == 1
        assert keys[0].startswith("IP_")

    def test_nested_list(self) -> None:
        m = _clean_mapping()
        obj = [["10.0.0.1", "8.8.8.8"], "dc01.lan"]
        out = sanitize(obj, m)
        assert isinstance(out, list)
        out_str = json.dumps(out)
        assert "10.0.0.1" not in out_str
        assert "8.8.8.8" in out_str
        assert "dc01.lan" not in out_str

    def test_nested_tuple(self) -> None:
        m = _clean_mapping()
        obj = ("10.0.0.5", ("dc01.lan", "evil.com"))
        out = sanitize(obj, m)
        assert isinstance(out, tuple)
        flat = str(out)
        assert "10.0.0.5" not in flat
        assert "evil.com" in flat

    def test_deeply_nested(self) -> None:
        m = _clean_mapping()
        obj = {"level1": {"level2": {"level3": "src 192.168.100.1"}}}
        out = sanitize(obj, m)
        assert "192.168.100.1" not in json.dumps(out)

    def test_non_string_values_pass_through(self) -> None:
        m = _clean_mapping()
        obj = {"count": 42, "flag": True, "nothing": None}
        out = sanitize(obj, m)
        assert out == obj  # type: ignore[comparison-overlap]


# ---------------------------------------------------------------------------
# 11. unsafe_residue — INDEPENDENT detection (does not share sanitize() code)
# ---------------------------------------------------------------------------


class TestResidueIndependence:
    def test_catches_leaked_private_ipv4(self) -> None:
        bad = "sanitize forgot 10.0.0.5 here"
        leaks = unsafe_residue(bad)
        assert any("10.0.0.5" in leak for leak in leaks)

    def test_catches_leaked_private_ipv6(self) -> None:
        bad = "leftover fe80::abcd in payload"
        leaks = unsafe_residue(bad)
        assert any("fe80::abcd" in leak for leak in leaks)

    def test_catches_leaked_mac(self) -> None:
        bad = "still has aa:bb:cc:dd:ee:ff"
        leaks = unsafe_residue(bad)
        assert any("aa:bb:cc:dd:ee:ff" in leak for leak in leaks)

    def test_catches_leaked_internal_host(self) -> None:
        bad = "going to dc01.lan"
        leaks = unsafe_residue(bad)
        assert any("dc01.lan" in leak for leak in leaks)

    def test_catches_leaked_internal_email(self) -> None:
        bad = "from user@corp.lan"
        leaks = unsafe_residue(bad)
        assert any("user@corp.lan" in leak for leak in leaks)

    def test_catches_leaked_home_path(self) -> None:
        bad = "/home/analyst/.ssh/id_rsa"
        leaks = unsafe_residue(bad)
        assert any("analyst" in leak for leak in leaks)

    def test_clean_string_returns_empty(self) -> None:
        good = "Public 8.8.8.8 evil.com CVE-2024-1234 T1055 port 443"
        assert unsafe_residue(good) == []

    def test_sanitized_labels_are_not_residue(self) -> None:
        """Labels like IP_01 or /home/USER_02 placed by sanitize() must not trip residue."""
        sanitized = "src IP_01 dst 8.8.8.8 opened /home/USER_02/file"
        assert unsafe_residue(sanitized) == []

    def test_residue_catches_what_sanitize_missed(self) -> None:
        """Simulate sanitize() having a bug — hand-craft a 'post-sanitize' string
        that still contains a raw private IP, and confirm residue catches it."""
        # Suppose sanitize() incorrectly left the IP in a corner case.
        almost_sanitized = "evidence: IP_01 reached 8.8.8.8, also 10.99.0.1 was there"
        leaks = unsafe_residue(almost_sanitized)
        assert any("10.99.0.1" in leak for leak in leaks)
        # The label (IP_01) must NOT be flagged
        assert not any("IP_01" in leak for leak in leaks)

    def test_extra_hosts_flagged_by_residue(self) -> None:
        bad = "myhost appeared in log"
        leaks = unsafe_residue(bad, extra_hosts=["myhost"])
        assert any("myhost" in leak for leak in leaks)


# ---------------------------------------------------------------------------
# 11b. unsafe_residue — independent NetBIOS/Windows bare-hostname safety net
# ---------------------------------------------------------------------------


class TestResidueNetbiosHosts:
    """``unsafe_residue`` re-implements a conservative NetBIOS/Windows bare-
    hostname detector from scratch (does NOT import redact.py) so a structural
    internal computer name that survived BOTH sanitize passes still trips the
    refuse-gate.  Positive: DESKTOP-/WIN-/-PC/-LAPTOP shapes are flagged even
    with empty known_values.  Negative: public domains, rule names, words, and
    product strings are NOT flagged."""

    def test_catches_desktop_prefix(self) -> None:
        leaks = unsafe_residue("outbound from DESKTOP-AB12 detected")
        assert any("DESKTOP-AB12" in leak for leak in leaks), leaks

    def test_catches_win_prefix(self) -> None:
        leaks = unsafe_residue("host WIN-7G3K9J2 beaconing")
        assert any("WIN-7G3K9J2" in leak for leak in leaks)

    def test_catches_pc_suffix(self) -> None:
        leaks = unsafe_residue("alert on FINANCE-PC at midnight")
        assert any("FINANCE-PC" in leak for leak in leaks)

    def test_catches_laptop_suffix(self) -> None:
        leaks = unsafe_residue("RECEPTION-LAPTOP failed preauth")
        assert any("RECEPTION-LAPTOP" in leak for leak in leaks)

    def test_no_known_values_needed(self) -> None:
        """Independence: fires WITHOUT known_values (redacter may have missed it)."""
        leaks = unsafe_residue("DESKTOP-AB12 here", known_values=())
        assert any("DESKTOP-AB12" in leak for leak in leaks)

    def test_public_domain_not_flagged(self) -> None:
        assert unsafe_residue("beacon to example.com and win-rar.com") == []

    def test_dotted_affix_fqdn_not_flagged(self) -> None:
        """A dotted FQDN whose first label looks like an affix passes (has a dot)."""
        assert unsafe_residue("served from desktop-themes.microsoft.com") == []

    def test_rule_name_not_flagged(self) -> None:
        leaks = unsafe_residue("ET MALWARE BPFDoor; GPL ATTACK_RESPONSE id check")
        assert leaks == [], f"rule strings must not be flagged: {leaks}"

    def test_dictionary_word_not_flagged(self) -> None:
        assert unsafe_residue("suspected malware activity observed") == []

    def test_product_string_not_flagged(self) -> None:
        assert unsafe_residue("Windows PowerShell Endpoint-Protection active") == []

    def test_bare_win_word_not_flagged(self) -> None:
        assert unsafe_residue("the WIN32 API and WIN architecture") == []

    def test_allowlisted_bare_host_not_flagged(self) -> None:
        leaks = unsafe_residue("DESKTOP-AB12 is allowed", allowlist=["DESKTOP-AB12"])
        assert not any("DESKTOP-AB12" in leak for leak in leaks)

    def test_opaque_label_not_flagged(self) -> None:
        """An opaque HOST_/SRV-style label must not be misflagged."""
        assert unsafe_residue("host HOST_01 reached evil.com") == []

    def test_dedup_same_host_once(self) -> None:
        """The same bare host appearing twice → flagged once (deduped)."""
        leaks = unsafe_residue("DESKTOP-AB12 and again DESKTOP-AB12")
        netbios = [leak for leak in leaks if "DESKTOP-AB12" in leak]
        assert len(netbios) == 1, f"expected one dedup'd flag, got {netbios}"


# ---------------------------------------------------------------------------
# 12. Allowlist — internal token passes verbatim; residue respects it
# ---------------------------------------------------------------------------


class TestAllowlist:
    def test_allowlisted_private_ip_passes_sanitize(self) -> None:
        m = _clean_mapping()
        out = sanitize("compromised 10.5.5.5 src", m, allowlist=["10.5.5.5"])
        assert "10.5.5.5" in out
        assert m.counters.get("IP", 0) == 0

    def test_non_allowlisted_private_ip_still_redacted(self) -> None:
        m = _clean_mapping()
        out = sanitize("10.5.5.5 and 10.6.6.6", m, allowlist=["10.5.5.5"])
        assert "10.5.5.5" in out
        assert "10.6.6.6" not in out

    def test_residue_skips_allowlisted_ip(self) -> None:
        """An allowlisted private IP must not be flagged by residue."""
        text = "compromised host 10.5.5.5 reached 8.8.8.8"
        leaks = unsafe_residue(text, allowlist=["10.5.5.5"])
        assert not any("10.5.5.5" in leak for leak in leaks)

    def test_residue_still_catches_non_allowlisted(self) -> None:
        text = "10.5.5.5 ok but 10.6.6.6 leaks"
        leaks = unsafe_residue(text, allowlist=["10.5.5.5"])
        assert any("10.6.6.6" in leak for leak in leaks)
        assert not any("10.5.5.5" in leak for leak in leaks)


# ---------------------------------------------------------------------------
# 13. redaction_summary — counts only, never values
# ---------------------------------------------------------------------------


class TestRedactionSummary:
    def test_counts_per_category(self) -> None:
        m = _clean_mapping()
        sanitize("10.0.0.1 10.0.0.2 aa:bb:cc:dd:ee:ff dc01.lan bob@corp.lan", m)
        summary = redaction_summary(m)
        assert summary.get("IP", 0) == 2
        assert summary.get("MAC", 0) == 1
        assert summary.get("HOST", 0) == 1
        assert summary.get("EMAIL", 0) == 1

    def test_summary_has_no_real_values(self) -> None:
        m = _clean_mapping()
        sanitize("10.0.0.1 aa:bb:cc:dd:ee:ff", m)
        summary = redaction_summary(m)
        for val in summary.values():
            assert isinstance(val, int)
        for key in summary:
            assert isinstance(key, str)

    def test_empty_mapping_returns_empty_dict(self) -> None:
        m = _clean_mapping()
        assert redaction_summary(m) == {}


# ---------------------------------------------------------------------------
# 14. Edge cases / integration scenarios
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_empty_string(self) -> None:
        m = _clean_mapping()
        assert sanitize("", m) == ""

    def test_no_identifiers(self) -> None:
        m = _clean_mapping()
        text = "no alerts today"
        assert sanitize(text, m) == text

    def test_home_path_label_not_double_redacted(self) -> None:
        """A /home/USER_01/... path from a previous sanitize pass must not
        be redacted again in a second sanitize call."""
        m = _clean_mapping()
        text = "/home/analyst/x"
        out1 = sanitize(text, m)
        # Applying sanitize again with the SAME mapping should be idempotent
        # because the label USER_01 doesn't match the username regex.
        out2 = sanitize(out1, m)
        assert out1 == out2

    def test_mixed_payload_json_roundtrip(self) -> None:
        case = {
            "alert": {
                "src_ip": "10.0.0.7",
                "dst_ip": "8.8.8.8",
                "hostname": "sensor.lan",
                "rule": "ET.MALWARE.BPFDoor",
            },
            "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "cve": "CVE-2024-1234",
            "technique": "T1055",
        }
        m = _clean_mapping()
        sanitized = sanitize(case, m)
        text = json.dumps(sanitized)

        # Private identifiers gone
        assert "10.0.0.7" not in text
        assert "sensor.lan" not in text

        # Public / safe identifiers preserved
        assert "8.8.8.8" in text
        assert "ET.MALWARE.BPFDoor" in text
        assert "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" in text
        assert "CVE-2024-1234" in text
        assert "T1055" in text

        # No residue
        leaks = unsafe_residue(text)
        assert leaks == []

    def test_desanitize_str_oracle_response(self) -> None:
        """Oracle returns a string referencing labels; desanitize restores them."""
        m = _clean_mapping()
        original_dict = {"src": "10.0.0.1", "dst": "8.8.8.8"}
        _ = sanitize(original_dict, m)
        # Simulate Oracle returning a string that uses the label
        lbl = m.forward["10.0.0.1"]
        oracle_resp = f"The source {lbl} is likely benign."
        rehydrated = desanitize(oracle_resp, m)
        assert "10.0.0.1" in rehydrated
        assert lbl not in rehydrated

    def test_public_ipv6_full_form_passes(self) -> None:
        """A full-form public IPv6 (8 groups) must not be redacted."""
        m = _clean_mapping()
        addr = "2001:4860:4860:0000:0000:0000:0000:8888"
        out = sanitize(f"google dns {addr}", m)
        assert addr in out

    def test_tuple_preserved_as_tuple(self) -> None:
        m = _clean_mapping()
        obj = ("10.0.0.1", "8.8.8.8")
        out = sanitize(obj, m)
        assert isinstance(out, tuple)

    def test_desanitize_non_string_types_pass_through(self) -> None:
        m = _clean_mapping()
        sanitize("10.0.0.1", m)  # populate mapping
        assert desanitize(42, m) == 42
        assert desanitize(None, m) is None
        assert desanitize(True, m) is True

    def test_sanitize_non_string_types_pass_through(self) -> None:
        m = _clean_mapping()
        assert sanitize(42, m) == 42  # type: ignore[arg-type]
        assert sanitize(None, m) is None  # type: ignore[arg-type]
        assert sanitize(True, m) is True  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# 15. Sanity: settings-driven suffixes flow through correctly
# ---------------------------------------------------------------------------


class TestSettingsSuffixes:
    """Verify that oracle_internal_suffixes from settings is respected."""

    def test_default_suffixes_active(self) -> None:
        """The four default suffixes must all trigger redaction."""
        targets = [
            "dc01.lan",
            "host.local",
            "svc.internal",
            "server.corp",
        ]
        for target in targets:
            m2 = _clean_mapping()
            out = sanitize(target, m2)
            assert target not in out, f"{target!r} should have been redacted"

    def test_extra_suffix_per_call(self) -> None:
        """Extra suffixes passed at call-time extend the default list."""
        m = _clean_mapping()
        out = sanitize("host.myco.example", m, extra_suffixes=[".myco.example"])
        assert "host.myco.example" not in out
        assert "HOST_" in out

    def test_extra_suffix_does_not_bleed_into_next_call(self) -> None:
        """Extra suffixes must be per-call only."""
        m = _clean_mapping()
        # First call with extra suffix
        sanitize("host.myco.example", m, extra_suffixes=[".myco.example"])
        # Second call without it — should NOT redact the same pattern
        m2 = _clean_mapping()
        out2 = sanitize("host.myco.example", m2)
        # Without the extra suffix, this is a public domain — passes through
        assert "host.myco.example" in out2

    @pytest.mark.parametrize(
        "suffix",
        [".lan", ".local", ".internal", ".corp"],
    )
    def test_each_default_suffix_independently(self, suffix: str) -> None:
        m = _clean_mapping()
        hostname = f"testhost{suffix}"
        out = sanitize(hostname, m)
        assert hostname not in out


# ---------------------------------------------------------------------------
# Fix 3: oracle_extra_hosts wired identically into sanitize + unsafe_residue
# ---------------------------------------------------------------------------


class TestOracleExtraHosts:
    """Fix M1: bare internal hostnames in ORACLE_EXTRA_HOSTS are redacted by
    both sanitize() and caught by unsafe_residue() when NOT listed.

    These tests verify the threading invariant: both calls receive the same
    extra_hosts tuple so there is no gap where residue passes the check but
    sanitize didn't cover it (and vice versa).
    """

    def test_sanitize_redacts_extra_host(self) -> None:
        """'appserver' listed in extra_hosts → sanitize tokenizes it."""
        m = _clean_mapping()
        out = sanitize("connection from appserver to 10.0.0.1", m, extra_hosts=["appserver"])
        assert "appserver" not in out
        assert "HOST_" in out

    def test_sanitize_does_not_redact_without_extra_host(self) -> None:
        """'appserver' NOT listed → passes through as a bare name (no suffix)."""
        m = _clean_mapping()
        out = sanitize("connection from appserver to 10.0.0.1", m)
        assert "appserver" in out

    def test_unsafe_residue_flags_bare_host_without_extra_hosts(self) -> None:
        """When extra_hosts=() (not listed), unsafe_residue does NOT flag 'appserver'
        because it cannot distinguish bare public hostnames from internal ones —
        that detection is the job of sanitize()+extra_hosts.

        This test documents the trust model: listing the host in extra_hosts is
        what makes sanitize cover it; residue only sees what sanitize missed.
        """
        payload = json.dumps({"hostname": "appserver"})
        leaks = unsafe_residue(payload)
        # 'appserver' is a bare word with no private-IP/MAC/suffix signal;
        # residue correctly does NOT flag it as a leak.
        assert not any("appserver" in leak for leak in leaks)

    def test_sanitize_extra_hosts_same_as_unsafe_residue_coverage(self) -> None:
        """Threading invariant: when extra_hosts=["appserver"] is threaded into both
        sanitize() and unsafe_residue(), the sanitized output is clean and residue
        does not flag 'appserver' in the sanitized payload.

        This mirrors the invariant in oracle/client.py: both calls get the same
        extra_hosts tuple.
        """
        extra_hosts = ["appserver"]
        m = _clean_mapping()
        raw = {"host_field": "appserver", "other": "normal text"}
        sanitized = sanitize(raw, m, extra_hosts=extra_hosts)
        payload_text = json.dumps(sanitized)
        # Post-sanitize, 'appserver' must not appear in the payload.
        assert "appserver" not in payload_text
        # Residue sweep with the SAME extra_hosts must report no leaks.
        leaks = unsafe_residue(payload_text, extra_hosts=extra_hosts)
        assert leaks == [], f"unexpected residue with matching extra_hosts: {leaks}"

    def test_sanitize_and_residue_same_extra_hosts_multiple_hosts(self) -> None:
        """Threading with multiple bare hostnames: DESKTOP-AB12 and FINANCE-PC."""
        extra_hosts = ["DESKTOP-AB12", "FINANCE-PC"]
        m = _clean_mapping()
        raw = "alert from DESKTOP-AB12 targeting FINANCE-PC"
        sanitized = sanitize(raw, m, extra_hosts=extra_hosts)
        assert "DESKTOP-AB12" not in sanitized
        assert "FINANCE-PC" not in sanitized
        leaks = unsafe_residue(sanitized, extra_hosts=extra_hosts)
        assert leaks == [], f"unexpected residue: {leaks}"


# ---------------------------------------------------------------------------
# 17. DNS-SD / underscore-led suffix-FQDNs  (incident 2026-07-08)
# ---------------------------------------------------------------------------
#
# Real eval traffic carried mDNS/DNS-SD service names in free text
# (``payload_printable`` / ``network.data.decoded``):
#
#   ".C..........\n_aaplcache._tcp.corp.lan....."   (real 0x0a DNS length byte)
#   "2~..........._aaplcache1._tcp.corp.lan....."   (nonprintables -> dots)
#
# The old replacement pattern required the first label to start [A-Za-z0-9],
# so ``_aaplcache._tcp.corp.lan`` sailed through sanitize un-redacted.  The
# residue detector (same first-label class) caught the first form only by
# ACCIDENT: json.dumps turned the newline into a literal ``\n``, handing it a
# fake alnum lead-in (flagged as ``n_aaplcache._tcp.corp.lan``).  The second
# (dot-prefixed) form was missed by BOTH paths — a silent-leak class.

_INCIDENT_DECODED = ".C..........\n_aaplcache._tcp.corp.lan....."
_INCIDENT_PRINTABLE = "2~..........._aaplcache1._tcp.corp.lan....."


class TestDnsSdServiceFqdns:
    def test_incident_decoded_string_redacted_in_json_context(self) -> None:
        """The exact incident string, inside a realistic case-dict context."""
        m = _clean_mapping()
        case = {
            "network": {"data": {"decoded": _INCIDENT_DECODED}},
            "message": "ET MALWARE Potential DNS C2 via TXT on sensor",
        }
        out = sanitize(case, m)
        outbound = json.dumps(out)
        assert "_aaplcache" not in outbound
        assert "corp.lan" not in outbound
        assert "HOST_" in outbound
        assert unsafe_residue(outbound) == []

    def test_incident_raw_form_flagged_by_detector(self) -> None:
        """Detector coverage of the incident shape on an UN-sanitized outbound
        string (this is what fail-closed refused on 2026-07-08)."""
        outbound = json.dumps({"decoded": _INCIDENT_DECODED})
        issues = unsafe_residue(outbound)
        assert any("aaplcache._tcp.corp.lan" in i for i in issues)

    def test_dot_run_prefixed_dns_sd_redacted(self) -> None:
        """payload_printable renders the DNS length byte as '.', so the
        service label follows a dot-run — must still be redacted."""
        m = _clean_mapping()
        out = sanitize(_INCIDENT_PRINTABLE, m)
        assert isinstance(out, str)
        assert "_aaplcache1" not in out
        assert "corp.lan" not in out
        assert unsafe_residue(json.dumps(out)) == []

    def test_clean_underscore_fqdn_redacts_whole_token(self) -> None:
        m = _clean_mapping()
        out = sanitize("query for _aaplcache._tcp.corp.lan observed", m)
        assert out == "query for HOST_01 observed"

    def test_joined_prefix_redacts_whole_token_not_partial(self) -> None:
        """Boundary pin: word-joined text redacts the WHOLE token — no
        partial-label mangling that leaves `.corp.lan` behind."""
        m = _clean_mapping()
        out = sanitize("seen dns_aaplcache._tcp.corp.lan in logs", m)
        assert out == "seen HOST_01 in logs"

    def test_public_dns_sd_untouched(self) -> None:
        """Non-internal suffix: DNS-SD names on public domains must pass."""
        m = _clean_mapping()
        text = "SRV _ldap._tcp.example.com and _service._tcp.evil.org queried"
        out = sanitize(text, m)
        assert out == text
        assert unsafe_residue(json.dumps(out)) == []

    def test_desanitize_round_trip(self) -> None:
        m = _clean_mapping()
        out = sanitize(_INCIDENT_DECODED, m)
        assert desanitize(out, m) == _INCIDENT_DECODED


class TestSuffixFqdnDetectorReplacerInvariant:
    """INVARIANT: any suffix-FQDN the residue detector would flag on the final
    outbound string must have been caught by the replacement pattern first
    (detector is a SUBSET of the replacer for the suffix-FQDN class).

    The two patterns are deliberately re-declared (sanitize path vs residue
    path must not fail together) — this test is what keeps their accepted
    label alphabets aligned.
    """

    _FIRST_LABELS = (
        "host01",
        "_aaplcache",
        "_x-9",
        "svc-01",
        "_MiXeD",
        "0start",
        "_0start",
        "_dns-sd",
    )
    _MIDDLES = ("", "._tcp", ".sub.zone", "._dns-sd._udp")
    _SUFFIXES = (".lan", ".local", ".internal", ".corp")
    _CONTEXTS = (
        "seen {} in traffic",
        "payload:\n{} end",
        'k="{}" v',
        "...{}...",
        "\\{} tail",
    )

    def test_detector_flag_implies_replacer_caught(self) -> None:
        """Loop the corpus through sanitize then the detector: nothing the
        detector accepts may survive the replacer (json.dumps included, since
        the detector runs on the dumped outbound string)."""
        for first in self._FIRST_LABELS:
            for mid in self._MIDDLES:
                for suffix in self._SUFFIXES:
                    fqdn = f"{first}{mid}{suffix}"
                    for ctx in self._CONTEXTS:
                        raw = ctx.format(fqdn)
                        m = _clean_mapping()
                        sanitized = sanitize(raw, m)
                        outbound = json.dumps(sanitized)
                        residue = [i for i in unsafe_residue(outbound) if "internal host" in i]
                        assert residue == [], (raw, sanitized, residue)

    def test_detector_coverage_of_underscore_labels(self) -> None:
        """The corpus is IN the detector's language: on a raw (un-sanitized)
        outbound string the detector flags every first-label shape — including
        underscore-led DNS-SD labels, no longer only by json-escape accident."""
        for first in self._FIRST_LABELS:
            fqdn = f"{first}._tcp.corp.lan"
            outbound = json.dumps(f"seen {fqdn} in traffic")
            issues = [i for i in unsafe_residue(outbound) if "internal host" in i]
            assert issues, f"detector missed {fqdn!r}"
