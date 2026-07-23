"""Unit tests for the eval-harness sanitizer.

The module is a near-verbatim copy of agentic-cybersecurity's
`pipeline/sanitize/core.py`; these tests assert the contract that
matters for soc-ai's specific use:

- private IPs / internal hostnames / MACs / internal emails / home
  paths get replaced with stable opaque labels;
- public IPs / domains / file hashes / CVE-ish identifiers pass
  through untouched;
- the round-trip (sanitize → desanitize) restores the original
  exactly;
- :func:`unsafe_residue` refuses on a deliberately-broken input.
"""

from __future__ import annotations

import time

from soc_ai.eval import sanitize as san


def test_private_ipv4_is_redacted_public_passes_through() -> None:
    """RFC1918 + CGNAT + loopback get labels; public IPs pass."""
    text = "Source 10.20.30.148 reached 8.8.8.8 via 100.64.0.1; localhost 127.0.0.1."
    out, m = san.sanitize(text)
    assert "10.20.30.148" not in out
    assert "100.64.0.1" not in out
    assert "127.0.0.1" not in out
    assert "8.8.8.8" in out  # public — preserved
    # Each private IP gets a distinct label.
    assert m.summary().get("IP", 0) == 3


def test_private_ipv6_is_redacted_public_passes() -> None:
    text = "remote 2606:4700::1 link-local fe80::1 loopback ::1"
    out, m = san.sanitize(text)
    # The public address is preserved whole.
    assert "2606:4700::1" in out
    # The link-local + loopback addresses are redacted (replaced
    # with labels, no longer present as standalone tokens).
    assert " fe80::1 " not in f" {out} "
    assert " ::1" not in f" {out} "
    assert m.summary().get("IP", 0) == 2


def test_internal_hostname_suffixes_are_redacted() -> None:
    text = "app01.lan and db01.lan and gateway.lan in the path"
    out, _ = san.sanitize(text)
    assert "app01.lan" not in out
    assert "db01.lan" not in out
    assert "gateway.lan" not in out
    assert "HOST_" in out


def test_bare_internal_host_redacts_only_via_extra_hosts() -> None:
    """No env-specific hostnames ship by default: a bare single-label name
    passes through unless the deployment lists it in extra_hosts
    (ORACLE_EXTRA_HOSTS). FQDN forms remain caught by the suffix rule."""
    out, _ = san.sanitize("connection from dbserver to 10.0.0.1")
    assert "dbserver" in out  # bare name, not configured → not redacted by default
    out2, _ = san.sanitize("connection from dbserver to 10.0.0.1", extra_hosts=["dbserver"])
    assert "dbserver" not in out2  # listed as an extra host → redacted
    assert "HOST_" in out2


def test_public_domain_passes_through() -> None:
    """Bare public domains aren't redacted — they're high-signal IOCs."""
    text = "DNS query for storyblok.com resolved to 3.166.135.86"
    out, _ = san.sanitize(text)
    assert "storyblok.com" in out
    assert "3.166.135.86" in out  # public IP


def test_file_hashes_pass_through() -> None:
    sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    text = f"Suspect hash {sha256} (CVE-2024-1234) on host app01.lan"
    out, _ = san.sanitize(text)
    assert sha256 in out
    assert "CVE-2024-1234" in out
    assert "app01.lan" not in out  # internal host (suffix) redacted


def test_mac_is_always_redacted() -> None:
    out, m = san.sanitize("aa:bb:cc:dd:ee:ff connected at 00-11-22-33-44-55")
    assert "aa:bb:cc:dd:ee:ff" not in out
    assert "00-11-22-33-44-55" not in out
    assert m.summary().get("MAC", 0) == 2


def test_home_path_redacts_username_only() -> None:
    out, _ = san.sanitize("opened /home/analyst/keys/id_rsa for reading")
    # /home/ + label + /keys/id_rsa — path tail preserved.
    assert "analyst" not in out
    assert "/home/USER_" in out
    assert "/keys/id_rsa" in out


def test_internal_email_redacted_public_email_preserved() -> None:
    out, m = san.sanitize("alert from alice@example.lan, cc to abuse@anthropic.com")
    assert "alice@example.lan" not in out
    assert "abuse@anthropic.com" in out
    assert m.summary().get("EMAIL", 0) == 1


def test_mapping_is_deterministic_within_a_run() -> None:
    """Two calls reusing the same Mapping reuse the same label."""
    m = san.Mapping()
    out1, _ = san.sanitize("first 10.0.0.1", mapping=m)
    out2, _ = san.sanitize("again 10.0.0.1", mapping=m)
    label1 = out1.split()[-1]
    label2 = out2.split()[-1]
    assert label1 == label2
    assert label1.startswith("IP_")


def test_desanitize_restores_originals() -> None:
    text = "alert from 10.20.30.148 to app01.lan via aa:bb:cc:dd:ee:ff"
    out, m = san.sanitize(text)
    rehydrated = san.desanitize(out, m)
    assert rehydrated == text


def test_unsafe_residue_catches_a_leaked_private_ip() -> None:
    """Deliberately-broken text gets rejected by the residue check."""
    bad = "after sanitize we still have 10.0.0.1 here"
    issues = san.unsafe_residue(bad)
    assert any("10.0.0.1" in i for i in issues)


def test_unsafe_residue_clean_when_text_is_actually_clean() -> None:
    text = "public IP 8.8.8.8 (no leak)"
    assert san.unsafe_residue(text) == []


def test_unsafe_residue_skips_label_placeholders() -> None:
    """Sanitizer-output labels like /home/USER_01 are NOT residue."""
    text = "opened /home/USER_01/.ssh and IP_03 reached 8.8.8.8"
    assert san.unsafe_residue(text) == []


def test_unsafe_residue_flags_bare_extra_host() -> None:
    """F10: the residue gate must accept ``extra_hosts`` (the operator's
    ORACLE_EXTRA_HOSTS) so a bare internal hostname that survived sanitize is
    caught before egress — mirroring the sanitize() side, which already takes
    it. Without the host listed the token is shape-indistinguishable from public
    infra and is (correctly) NOT flagged."""
    payload = "beacon observed from spark1 to 8.8.8.8"
    # Listed as an internal host → flagged.
    issues = san.unsafe_residue(payload, extra_hosts=["spark1"])
    assert any("spark1" in i for i in issues)
    # Not listed → not flagged (bare name looks like public infra).
    assert san.unsafe_residue(payload) == []


def test_sanitize_and_unsafe_residue_extra_hosts_agree() -> None:
    """F10 invariant: threading the SAME extra_hosts into sanitize() and
    unsafe_residue() means the sanitized output has no residual internal host."""
    hosts = ["dc01", "gateway"]
    out, _ = san.sanitize("traffic dc01 -> gateway", extra_hosts=hosts)
    assert "dc01" not in out
    assert "gateway" not in out
    assert san.unsafe_residue(out, extra_hosts=hosts) == []


def test_redos_adversarial_inputs_complete_fast() -> None:
    """Bounded quantifiers: a 40k-char adversarial run with no valid match must
    not cause catastrophic backtracking. Both the email rule and the internal-
    suffix host rule run; the whole sanitize must finish well under 1s."""
    email_bomb = ("a-" * 20000) + "@x"  # no valid TLD → email rule must bail fast
    host_bomb = ("a." * 20000) + "lan"  # long label run before a suffix-looking tail
    for payload in (email_bomb, host_bomb):
        start = time.perf_counter()
        san.sanitize(payload, extra_suffixes=[".lan"])
        san.unsafe_residue(payload, extra_suffixes=[".lan"])
        elapsed = time.perf_counter() - start
        assert elapsed < 1.0, f"ReDoS: sanitize took {elapsed:.2f}s on {payload[:20]!r}…"


# ---------------------------------------------------------------------------
# DNS-SD / underscore-led suffix-FQDNs (incident 2026-07-08 — this module's
# unsafe_residue is what refused the eval oracle send; see eval/harness.py)
# ---------------------------------------------------------------------------

_INCIDENT_DECODED = ".C..........\n_aaplcache._tcp.corp.lan....."
_INCIDENT_PRINTABLE = "2~..........._aaplcache1._tcp.corp.lan....."


def test_dns_sd_incident_string_redacted_and_residue_clean() -> None:
    """Regression: the exact free-text incident string (real newline = the DNS
    length byte 0x0a) is redacted to a HOST label, and the residue sweep over
    the json.dumps outbound form passes afterwards."""
    import json

    out, m = san.sanitize(_INCIDENT_DECODED)
    assert "_aaplcache" not in out
    assert "corp.lan" not in out
    assert "HOST_" in out
    assert san.unsafe_residue(json.dumps(out)) == []
    # Reversible: the oracle's answer rehydrates to the original bytes.
    assert san.desanitize(out, m) == _INCIDENT_DECODED


def test_dns_sd_dot_run_prefixed_form_redacted() -> None:
    """payload_printable renders nonprintables as dots, so the service label
    follows a dot-run — previously missed by BOTH sanitize and the detector."""
    import json

    out, _ = san.sanitize(_INCIDENT_PRINTABLE)
    assert "_aaplcache1" not in out
    assert "corp.lan" not in out
    assert san.unsafe_residue(json.dumps(out)) == []


def test_dns_sd_joined_token_redacts_whole_fqdn() -> None:
    """Boundary pin: word-joined text redacts the whole token; no partial-label
    mangling that leaves `.corp.lan` behind."""
    out, _ = san.sanitize("seen dns_aaplcache._tcp.corp.lan in logs")
    assert out == "seen HOST_01 in logs"


def test_public_dns_sd_untouched() -> None:
    """DNS-SD names on non-internal suffixes are high-signal — must pass."""
    text = "SRV _ldap._tcp.example.com and _service._tcp.evil.org queried"
    out, _ = san.sanitize(text)
    assert out == text
    assert san.unsafe_residue(text) == []


def test_suffix_fqdn_detector_replacer_invariant() -> None:
    """INVARIANT: anything unsafe_residue would flag as a residual internal
    host on the outbound (json.dumps) string must be caught by sanitize first.
    (In this module both share _build_internal_host_re, so the invariant is
    structural — this test guards against the paths being split later.)"""
    import json

    first_labels = ("host01", "_aaplcache", "_x-9", "svc-01", "_MiXeD", "0start", "_0start")
    middles = ("", "._tcp", ".sub.zone")
    suffixes = (".lan", ".local", ".internal", ".corp")
    contexts = ("seen {} in traffic", "payload:\n{} end", 'k="{}" v', "...{}...")
    for first in first_labels:
        for mid in middles:
            for suffix in suffixes:
                fqdn = f"{first}{mid}{suffix}"
                for ctx in contexts:
                    raw = ctx.format(fqdn)
                    out, _ = san.sanitize(raw)
                    outbound = json.dumps(out)
                    residue = [i for i in san.unsafe_residue(outbound) if "internal host" in i]
                    assert residue == [], (raw, out, residue)
                # Detector coverage: the raw dumped form IS flagged.
                issues = san.unsafe_residue(json.dumps(f"seen {fqdn} x"))
                assert any("internal host" in i for i in issues), fqdn
