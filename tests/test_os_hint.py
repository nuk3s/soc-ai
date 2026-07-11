"""Tests for the telemetry-domain OS classifier (:mod:`soc_ai.tools.os_hint`).

The classifier exists to answer the OS-consistency question for a TLS-only host
that sends no User-Agent: infer the OS from the vendor telemetry it talks to
(Apple/Windows/Linux/Android), always carrying the matched domains as evidence.
The load-bearing property is the BPFDoor guard — "Linux" is NEVER inferred from
the absence of other families; it requires POSITIVE distro telemetry.
"""

from __future__ import annotations

from soc_ai.tools.os_hint import os_hint_from_domains

# The real production Apple-device domain set that motivated the feature: the
# host's own telemetry, mixed with a couple of non-OS services (Proton) that must
# NOT be treated as OS signals.
APPLE_PROD_DOMAINS = [
    "gdmf.apple.com",
    "mesu.apple.com",
    "gateway.icloud.com",
    "_aaplcache._tcp.local",
    "drive-api.proton.me",  # a real service, NOT an OS signal
]

WINDOWS_DOMAINS = [
    "www.msftconnecttest.com",
    "dns.msftncsi.com",
    "fe2.update.microsoft.com",
    "settings-win.data.microsoft.com",
]

LINUX_DOMAINS = [
    "connectivity-check.ubuntu.com",
    "archive.ubuntu.com",
    "deb.debian.org",
]

ANDROID_DOMAINS = [
    "android.clients.google.com",
    "mtalk.google.com",
    "connectivitycheck.gstatic.com",
]

# Domains that are real services but say nothing about the OS — a host that only
# talks to these is genuinely unknown, not any OS.
NON_OS_DOMAINS = [
    "drive-api.proton.me",
    "brave.com",
    "cdn.jsdelivr.net",
    "d1234.cloudfront.net",
    "example.com",
]


# ---------------------------------------------------------------------------
# Apple — the prod set. os macos (the _aaplcache mac-specific signal narrows it),
# strong, apple domains in signals, proton NOT a signal.
# ---------------------------------------------------------------------------


def test_apple_prod_set_is_macos_strong() -> None:
    hint = os_hint_from_domains(APPLE_PROD_DOMAINS)
    assert hint is not None
    # _aaplcache is a mac-family desktop signal, so the coarse "apple" narrows to macos.
    assert hint["os"] == "macos"
    assert hint["confidence"] == "strong"
    # The apple telemetry domains are the evidence…
    assert any("apple.com" in s or "icloud.com" in s or "aaplcache" in s for s in hint["signals"])
    # …and a non-OS service (Proton) is NOT surfaced as an OS signal.
    assert not any("proton" in s for s in hint["signals"])


def test_apple_without_mac_specific_signal_is_coarse_apple() -> None:
    # Shared Apple telemetry with NO mac-specific token → honest coarse "apple".
    hint = os_hint_from_domains(
        ["gateway.icloud.com", "1-courier.push.apple.com", "gdmf.apple.com"]
    )
    assert hint is not None
    assert hint["os"] == "apple"
    assert hint["confidence"] == "strong"


def test_apple_subdomain_and_trailing_dot_match() -> None:
    # Subdomain (x.gdmf.apple.com) and FQDN trailing dot must both match.
    hint = os_hint_from_domains(["x.gdmf.apple.com.", "GATEWAY.ICLOUD.COM"])
    assert hint is not None
    assert hint["os"] == "apple"
    assert hint["confidence"] == "strong"


def test_apple_lookalike_suffix_does_not_match() -> None:
    # notapple.com / applecom.evil.com must NOT be read as Apple telemetry.
    assert os_hint_from_domains(["notapple.com", "applecom.evil.example"]) is None


# ---------------------------------------------------------------------------
# Windows / Linux / Android — each named family, strong.
# ---------------------------------------------------------------------------


def test_windows_set_is_windows_strong() -> None:
    hint = os_hint_from_domains(WINDOWS_DOMAINS)
    assert hint is not None
    assert hint["os"] == "windows"
    assert hint["confidence"] == "strong"
    assert any("msft" in s or "microsoft.com" in s for s in hint["signals"])


def test_linux_distro_set_is_linux_strong() -> None:
    hint = os_hint_from_domains(LINUX_DOMAINS)
    assert hint is not None
    assert hint["os"] == "linux"
    assert hint["confidence"] == "strong"
    assert any("ubuntu.com" in s or "debian.org" in s for s in hint["signals"])


def test_android_set_is_android_strong() -> None:
    hint = os_hint_from_domains(ANDROID_DOMAINS)
    assert hint is not None
    assert hint["os"] == "android"
    assert hint["confidence"] == "strong"
    assert any("google.com" in s or "gstatic.com" in s for s in hint["signals"])


# ---------------------------------------------------------------------------
# Conflict — two strong families → weak, os None, signals from BOTH ("mixed").
# ---------------------------------------------------------------------------


def test_apple_plus_windows_is_mixed_weak_none() -> None:
    hint = os_hint_from_domains(["gdmf.apple.com", "gateway.icloud.com", "dns.msftncsi.com"])
    assert hint is not None
    assert hint["os"] is None
    assert hint["confidence"] == "weak"
    # Both families must be visible in the evidence (the "mixed" signal).
    joined = " ".join(hint["signals"])
    assert "apple.com" in joined or "icloud.com" in joined
    assert "msftncsi.com" in joined


# ---------------------------------------------------------------------------
# Nothing matched → None. (Proton/Brave/generic CDNs are NOT OS signals.)
# ---------------------------------------------------------------------------


def test_non_os_domains_return_none() -> None:
    assert os_hint_from_domains(NON_OS_DOMAINS) is None


def test_empty_input_returns_none() -> None:
    assert os_hint_from_domains([]) is None
    assert os_hint_from_domains(["", "   ", None]) is None  # type: ignore[list-item]


# ---------------------------------------------------------------------------
# THE load-bearing property: "Linux needs positive evidence".
# ---------------------------------------------------------------------------


def test_linux_never_inferred_from_absence_of_others() -> None:
    # A pure-Apple host, with ZERO Linux telemetry, must never come back linux —
    # this is the BPFDoor "Linux backdoor on a MacBook" guard.
    hint = os_hint_from_domains(APPLE_PROD_DOMAINS)
    assert hint is not None
    assert hint["os"] != "linux"

    # Even a host talking ONLY to non-OS services yields None, never linux.
    assert os_hint_from_domains(NON_OS_DOMAINS) is None

    # And an Apple + non-OS mix is still Apple-family, never linux.
    mixed = os_hint_from_domains(["gateway.icloud.com", "drive-api.proton.me", "brave.com"])
    assert mixed is not None
    assert mixed["os"] != "linux"


def test_signals_are_capped_and_deduped() -> None:
    # Many duplicate/case-variant Apple domains → deduped, capped at 5.
    noisy = [f"host{i}.push.apple.com" for i in range(10)] + [
        "GDMF.APPLE.COM",
        "gdmf.apple.com.",  # dupe of the above after normalize
    ]
    hint = os_hint_from_domains(noisy)
    assert hint is not None
    assert len(hint["signals"]) <= 5
    # Case/trailing-dot variants of gdmf.apple.com collapse to one entry.
    assert hint["signals"].count("gdmf.apple.com") <= 1
