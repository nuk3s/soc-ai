"""Infer a host's OS from the telemetry domains it talks to — the evidence a
modern TLS-only device leaves even when it never sends a User-Agent.

Why this exists (the BPFDoor false-positive that motivated it): a hunt asserted
a "BPFDoor Linux backdoor" on a host that was in fact a MacBook. ``host_summary``
could not contradict the claim because its only OS signal was the HTTP
User-Agent (and the ``zeek.software`` line), both empty for a TLS-only Apple
device — so ``device_os_guess`` came back ``None`` and the "Linux" rule name went
unchallenged. But the evidence WAS on the wire and unused: the host's own DNS
queries / TLS SNI were overwhelmingly Apple telemetry (``gdmf.apple.com``,
``mesu.apple.com``, ``gateway.icloud.com``, ``*.push.apple.com``, ``_aaplcache*``).
This module turns that traffic into an OS hint so the OS-consistency check the
hunt prompt now demands is ANSWERABLE from data the grid already has.

Design contract — an OS hint is EVIDENCE, never a bare fact:

- Every hint carries the matched domains (``signals``) so the agent and analyst
  SEE what the call was made from, exactly like ``host_summary``'s ``evidence``
  strings. A label with no domains behind it is not something this returns.
- The heuristics only ever fire on POSITIVE vendor-telemetry evidence. Critically
  — and this is the whole BPFDoor lesson — **"Linux" requires positive distro
  telemetry** (``connectivity-check.ubuntu.com``, ``deb.debian.org``, a Fedora /
  Arch mirror). The ABSENCE of Apple/Windows/Android signals is NOT evidence of
  Linux; a MacBook that happens to send no Apple telemetry in the window is
  "unknown", never "linux". This is enforced structurally: ``linux`` is only ever
  set when a ``_LINUX`` pattern actually matched (see :data:`_FAMILIES`), so no
  code path can reach ``os="linux"`` from the mere absence of other families.
- Conflicting strong evidence (Apple AND Windows domains from one IP — a NAT gate
  or a multi-device host) collapses to ``os=None`` + ``confidence="weak"`` with
  signals from BOTH families, so the agent is told "mixed", not handed a coin-flip.

Pure function, no I/O — this is the independently unit-testable core. The wiring
into :mod:`soc_ai.tools.host_summary` lives there, not here.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from typing import Literal, TypedDict

# The coarse OS families this classifier can name. ``apple`` is the deliberate
# catch-all for "an Apple device we can't split into macOS vs iOS" — most Apple
# telemetry (push.apple.com, gateway.icloud.com, gdmf/mesu) is shared across
# macOS and iOS, so we only narrow to ``macos`` / ``ios`` on a mac/iOS-SPECIFIC
# signal and otherwise report the honest coarse ``apple``.
OsLabel = Literal["macos", "ios", "windows", "linux", "android", "apple"]
Confidence = Literal["strong", "weak"]


class OsHint(TypedDict):
    """An evidence-bearing OS guess. ``signals`` is never empty when ``os`` or a
    mixed verdict is reported — the matched domains ARE the justification."""

    os: OsLabel | None
    confidence: Confidence
    signals: list[str]


# Family key -> what family a matched pattern votes for. Kept separate from the
# regexes so the "mixed" conflict logic can reason over families, not patterns.
_Family = Literal["apple", "windows", "linux", "android"]

# How many matched-domain signals to carry in a hint. Enough to be convincing,
# capped so a chatty host doesn't bloat the tool result / next-turn context.
_MAX_SIGNALS = 5


def _p(pattern: str) -> re.Pattern[str]:
    """Case-insensitive compile — vendor domains are matched case-folded and the
    query names on the wire vary in case."""
    return re.compile(pattern, re.IGNORECASE)


# ---------------------------------------------------------------------------
# Heuristic table — curated from KNOWN vendor telemetry endpoints.
#
# Each entry is (family, os_when_matched, regex). ``os_when_matched`` is the
# LABEL a match contributes: usually the coarse family (``apple``/``windows``/
# ``linux``/``android``), but a mac- or iOS-specific endpoint narrows to
# ``macos`` / ``ios``. Matching is on the full FQDN (trailing dot stripped,
# lower-cased). Anchors: ``(^|\.)vendor\.com$`` matches the domain AND any
# subdomain (``x.gdmf.apple.com``) but not a look-alike suffix
# (``notapple.com``); a leading ``_`` label (``_aaplcache._tcp``) is matched with
# a substring rule since it's a service-discovery token, not a registrable name.
#
# Sources verified via vendor docs / well-known-endpoint lists:
#   - Apple: support.apple.com "about macOS/iOS network connections" — gdmf
#     (software lookup), mesu (update catalogs), gateway.icloud.com (iCloud),
#     *.push.apple.com (APNs), guzzoni (Siri), *.aaplimg.com (Apple CDN),
#     _aaplcache._tcp (Content Caching / AirDrop Bonjour advert).
#   - Windows: msftconnecttest.com + dns.msftncsi.com (NCSI connectivity probe),
#     *.windowsupdate.com + *.update.microsoft.com (WU), settings-win.data.
#     microsoft.com (telemetry), ctldl.windowsupdate.com (cert trust list).
#   - Linux: connectivity-check.ubuntu.com (NetworkManager probe),
#     archive/security.ubuntu.com, deb.debian.org, *.fedoraproject.org,
#     *.archlinux.org — DISTRO package/connectivity infra (positive evidence).
#   - Android: android.clients.google.com + mtalk.google.com (GCM/FCM),
#     connectivitycheck.gstatic.com (captive-portal probe). *.googlevideo.com is
#     weak (any YouTube client) so it is intentionally OMITTED, not classified.
# ---------------------------------------------------------------------------

# (family, os_label_when_matched, compiled_regex)
_FAMILIES: tuple[tuple[_Family, OsLabel, re.Pattern[str]], ...] = (
    # --- Apple: mac/iOS-SPECIFIC narrowing signals FIRST (they win the label) ---
    # Content Caching / AirDrop Bonjour advert — a mac-family desktop signal.
    ("apple", "macos", _p(r"_aaplcache\b")),
    # --- Apple: shared macOS+iOS telemetry (coarse "apple") ---
    ("apple", "apple", _p(r"(^|\.)gdmf\.apple\.com$")),  # software update lookup
    ("apple", "apple", _p(r"(^|\.)mesu\.apple\.com$")),  # mobile/desktop update catalog
    ("apple", "apple", _p(r"(^|\.)xp\.apple\.com$")),  # experiment/telemetry
    ("apple", "apple", _p(r"(^|\.)push\.apple\.com$")),  # APNs (*.push.apple.com)
    ("apple", "apple", _p(r"(^|\.)gateway\.icloud\.com$")),  # iCloud gateway
    ("apple", "apple", _p(r"(^|\.)bag\.itunes\.apple\.com$")),  # iTunes/App Store bag
    ("apple", "apple", _p(r"(^|\.)guzzoni\.apple\.com$")),  # Siri
    ("apple", "apple", _p(r"(^|\.)icloud\.com$")),  # iCloud services
    ("apple", "apple", _p(r"(^|\.)aaplimg\.com$")),  # Apple CDN images
    # Generic *.apple.com LAST within the family so a specific host above wins the
    # signal slot; still a positive Apple vote.
    ("apple", "apple", _p(r"(^|\.)apple\.com$")),
    # --- Windows ---
    ("windows", "windows", _p(r"(^|\.)msftconnecttest\.com$")),  # NCSI probe
    ("windows", "windows", _p(r"(^|\.)dns\.msftncsi\.com$")),  # NCSI DNS probe
    ("windows", "windows", _p(r"(^|\.)windowsupdate\.com$")),  # WU (incl. ctldl.)
    ("windows", "windows", _p(r"(^|\.)update\.microsoft\.com$")),  # WU
    ("windows", "windows", _p(r"(^|\.)settings-win\.data\.microsoft\.com$")),  # telemetry
    # --- Linux: POSITIVE distro telemetry ONLY (the BPFDoor guard) ---
    ("linux", "linux", _p(r"(^|\.)connectivity-check\.ubuntu\.com$")),  # NM probe
    ("linux", "linux", _p(r"(^|\.)archive\.ubuntu\.com$")),
    ("linux", "linux", _p(r"(^|\.)security\.ubuntu\.com$")),
    ("linux", "linux", _p(r"(^|\.)ubuntu\.com$")),
    ("linux", "linux", _p(r"(^|\.)deb\.debian\.org$")),
    ("linux", "linux", _p(r"(^|\.)debian\.org$")),
    ("linux", "linux", _p(r"(^|\.)fedoraproject\.org$")),
    ("linux", "linux", _p(r"(^|\.)archlinux\.org$")),
    # --- Android ---
    ("android", "android", _p(r"(^|\.)android\.clients\.google\.com$")),  # GCM/FCM
    ("android", "android", _p(r"(^|\.)mtalk\.google\.com$")),  # FCM long-lived
    ("android", "android", _p(r"(^|\.)connectivitycheck\.gstatic\.com$")),  # captive probe
)


def _normalize(domain: str) -> str:
    """Lower-case + strip a single trailing dot (FQDN root) for matching.

    DNS query names on the wire are frequently fully-qualified with a trailing
    dot (``gdmf.apple.com.``) and vary in case; the heuristic anchors expect a
    bare lower-case name so the ``$`` end-anchor lands on ``.com`` not ``.``.
    """
    return domain.strip().rstrip(".").lower()


def os_hint_from_domains(domains: Iterable[str]) -> OsHint | None:
    """Classify a host's OS from the telemetry domains it queried / SNI'd.

    Args:
        domains: the domain strings a host was seen talking to — DNS query names
            and/or TLS SNI server-names. Duplicates and case / trailing-dot
            variants are fine; they're normalized and deduped here.

    Returns:
        An :class:`OsHint` whose ``signals`` are the matched domains (deduped,
        capped at :data:`_MAX_SIGNALS`), or ``None`` when nothing matched. The
        verdict rules:

        - **Single family matched** → ``os`` = that family's label (narrowed to
          ``macos`` if a mac-specific signal like ``_aaplcache`` fired, else the
          coarse family), ``confidence="strong"``, ``signals`` from that family.
        - **Two-or-more families matched** → a conflict: ``os=None``,
          ``confidence="weak"``, ``signals`` drawn from BOTH families (so the
          agent reads it as "mixed — possible NAT / multi-device", not a guess).
        - **Nothing matched** → ``None`` (Proton, Brave, generic CDNs and the
          like are deliberately NOT OS signals, so a host that only talks to
          those is genuinely unknown).

    "Linux needs positive evidence" is enforced structurally: ``linux`` only
    appears in the result when a ``_LINUX`` pattern actually matched a domain —
    there is no branch that infers Linux from the absence of other families. A
    MacBook with zero Linux telemetry can never come back ``os="linux"``.
    """
    # Per-family ORDERED-unique matched domains (dict preserves first-seen order
    # and dedupes) + the label each family's matches voted for. Using the domain
    # as the key means x.gdmf.apple.com and gdmf.apple.com both land once.
    matched: dict[_Family, dict[str, None]] = {}
    family_label: dict[_Family, OsLabel] = {}

    for raw in domains:
        if not raw:
            continue
        name = _normalize(raw)
        if not name:
            continue
        for family, os_label, pattern in _FAMILIES:
            if pattern.search(name):
                matched.setdefault(family, {})[name] = None
                # A mac/iOS-specific label (macos/ios) is more specific than the
                # coarse family label — let it win the family's reported OS.
                if family not in family_label or os_label != family:
                    family_label[family] = os_label
                # One domain can only sensibly belong to one family; stop at the
                # first matching pattern so it isn't double-counted.
                break

    if not matched:
        return None

    families = list(matched)

    # --- conflict: strong evidence for 2+ families = "mixed", os None, weak ---
    if len(families) >= 2:
        signals: list[str] = []
        # Round-robin one domain per family so the signal cap shows the conflict
        # (both families visible) rather than 5 of whichever family sorted first.
        per_family = [list(matched[f]) for f in families]
        idx = 0
        while len(signals) < _MAX_SIGNALS and any(idx < len(d) for d in per_family):
            for d in per_family:
                if idx < len(d) and len(signals) < _MAX_SIGNALS:
                    signals.append(d[idx])
            idx += 1
        return OsHint(os=None, confidence="weak", signals=signals)

    # --- single family: strong, with that family's evidence ---
    (family,) = families
    signals = list(matched[family])[:_MAX_SIGNALS]
    return OsHint(os=family_label[family], confidence="strong", signals=signals)
