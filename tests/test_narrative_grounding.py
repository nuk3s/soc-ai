"""Tests for the chat narrative grounding validator (Layer 2 of the chat trust fix).

The canonical bug: a chat turn that made ZERO tool calls answered "what was this host
doing?" by fabricating a hostname (DESKTOP-JSM4N2P), internal DNS (ad.local,
wsus.internal), and SMB file-share activity — none of it real (the host was an Apple
device). These tests pin the grader: it flags whole-cloth fabrication, never flags a
fact present in the seed context (the alert's own host/IP/domain), and never flags an
answer whose claims all appear in a tool result.
"""

from __future__ import annotations

from soc_ai.agent.narrative_grounding import (
    UNVERIFIED_CAVEAT,
    check_narrative_grounding,
    extract_artifacts,
)


def test_zero_tool_fabricated_host_and_dns_is_flagged() -> None:
    """(1) Answer asserts a hostname + internal DNS with meta.tools == [] and a seed
    context that does NOT contain them → flagged."""
    answer = (
        "**The host was a domain-joined workstation.**\n"
        "- Hostname `DESKTOP-JSM4N2P`\n"
        "- Resolved `ad.local` and `wsus.internal`\n"
        "- Opened SMB file shares against the file server"
    )
    seed = "Alert: ET SCAN something (10.0.0.5 → 10.0.0.9)\nVerdict reached: false_positive"
    g = check_narrative_grounding(answer, seed_context=seed, tool_evidence=[])
    assert g.grounded is False
    assert "DESKTOP-JSM4N2P" in g.ungrounded
    assert "ad.local" in g.ungrounded
    assert "wsus.internal" in g.ungrounded
    assert g.reason and "context" in g.reason


def test_alert_own_host_and_ip_from_seed_context_is_not_flagged() -> None:
    """(2) Answer states the alert's OWN host/IP/domain (present in the seeded
    context) with no tools → NOT flagged (no false positive)."""
    seed = (
        "Alert: ET POLICY DNS (10.0.0.5 → 8.8.8.8) on host WIN11-LAB01\n"
        "Verdict reached: false_positive (confidence 0.85)\n"
        "Why: WIN11-LAB01 at 10.0.0.5 made a routine lookup to dns.google"
    )
    answer = (
        "**This was the lab workstation WIN11-LAB01 doing a normal DNS lookup.**\n"
        "- `WIN11-LAB01` (10.0.0.5) queried `dns.google` at 8.8.8.8\n"
        "- Nothing malicious about it."
    )
    g = check_narrative_grounding(answer, seed_context=seed, tool_evidence=[])
    assert g.grounded is True
    # The artifacts were detected, but all are grounded in the seed context.
    assert "WIN11-LAB01" in g.asserted
    assert g.ungrounded == []


def test_claims_grounded_in_tool_result_are_not_flagged() -> None:
    """(3) Answer whose claims all appear in a tool result → not flagged."""
    seed = "Alert: ET MALWARE beacon (10.0.0.5 → 203.0.113.7)"
    tool_evidence = [
        {
            "tool": "t_query_events_oql",
            "result": (
                "hit _id=ev-1 host.name=DESKTOP-JSM4N2P dns.question.name=ad.local dst=10.0.0.9"
            ),
        }
    ]
    answer = (
        "**The host DESKTOP-JSM4N2P resolved ad.local.**\n- Confirmed from the zeek.dns hit (ev-1)."
    )
    g = check_narrative_grounding(answer, seed_context=seed, tool_evidence=tool_evidence)
    assert g.grounded is True
    assert g.ungrounded == []


def test_anchored_real_artifact_does_not_excuse_fabricated_ones() -> None:
    """A grounded artifact (a tool hit for DESKTOP-JSM4N2P) must NOT wave through an
    ungrounded one (ad.local). One ground does not excuse a fabricated per-event fact."""
    seed = "Alert: ET SCAN (10.0.0.5 → 10.0.0.9)"
    tool_evidence = [{"tool": "t_query_events_oql", "result": "host.name=DESKTOP-JSM4N2P seen"}]
    answer = "**Host `DESKTOP-JSM4N2P`** — also looked like it touched `ad.local`."
    g = check_narrative_grounding(answer, seed_context=seed, tool_evidence=tool_evidence)
    assert g.grounded is False
    assert "ad.local" in g.ungrounded
    assert "DESKTOP-JSM4N2P" not in g.ungrounded  # grounded by the tool result


def test_real_alert_ip_with_fabricated_host_dns_smb_is_flagged() -> None:
    """Regression for investigation 01KW0FZ6…: the answer cited the alert's REAL IP
    (grounded in the seed) but fabricated a hostname, internal DNS, and SMB — none of it
    pulled (meta.tools == []). The grounded alert IP must not excuse the fabrication."""
    seed = (
        "Alert: ET DROP Spamhaus DROP Listed Traffic (10.20.30.66 → 203.0.113.4)\n"
        "Verdict reached: true_positive (0.72) — TLS to a DROP-listed IP, SNI cdn.data-2219.com"
    )
    answer = (
        "**The host 10.20.30.66 made a single outbound TLS connection to the DROP IP.**\n"
        "- Hostname `DESKTOP-JSM4N2P` (a Windows workstation)\n"
        "- Queried internal domains `ad.local` and `wsus.internal`\n"
        "- Opened SMB file shares against the file server `10.20.30.10`"
    )
    g = check_narrative_grounding(answer, seed_context=seed, tool_evidence=[])
    assert g.grounded is False
    assert "DESKTOP-JSM4N2P" in g.ungrounded
    assert "ad.local" in g.ungrounded and "wsus.internal" in g.ungrounded
    assert "10.20.30.10" in g.ungrounded
    assert "10.20.30.66" not in g.ungrounded  # the alert's real IP, grounded in the seed


def test_lowercase_hostname_is_extracted_and_flagged() -> None:
    """F21: a fabricated hostname written in lowercase (common LLM prose style)
    must still be detected — the hostname regex was case-sensitive, so a whole-
    cloth `desktop-jsm4n2p` claim evaded the grounding check purely by
    capitalization."""
    seed = "Alert: ET SCAN (10.0.0.5 → 10.0.0.9)"
    answer = (
        "**The traffic originated from workstation desktop-jsm4n2p per our "
        "inventory, so this is benign.**"
    )
    a = extract_artifacts(answer)
    assert "desktop-jsm4n2p" in a.hostnames
    g = check_narrative_grounding(answer, seed_context=seed, tool_evidence=[])
    assert g.grounded is False
    assert "desktop-jsm4n2p" in g.ungrounded


def test_no_concrete_artifacts_is_not_flagged() -> None:
    """A purely qualitative answer with no concrete identifiers is never flagged."""
    answer = (
        "**I haven't pulled this host's DNS yet — let me check.**\n"
        "- I can't say what it resolved without querying zeek.dns first."
    )
    g = check_narrative_grounding(answer, seed_context="Alert: x", tool_evidence=[])
    assert g.grounded is True
    assert g.asserted == []


def test_specific_ip_not_in_alert_is_flagged() -> None:
    """A concrete IP that appears in neither the alert/seed nor a tool result is an
    ungrounded assertion."""
    seed = "Alert: ET SCAN (10.0.0.5 → 10.0.0.9)"
    answer = "**The host beaconed to 198.51.100.23 every 30s.**"
    g = check_narrative_grounding(answer, seed_context=seed, tool_evidence=[])
    assert g.grounded is False
    assert "198.51.100.23" in g.ungrounded


def test_extract_artifacts_shapes() -> None:
    """The detector pulls the artifact shapes a hallucination invents."""
    a = extract_artifacts(
        "Host DESKTOP-JSM4N2P resolved ad.local and wsus.internal, "
        "talked to 10.1.2.3, ja3 e7d705a3286e19ea42f587b344ee6865, opened SMB shares."
    )
    assert "DESKTOP-JSM4N2P" in a.hostnames
    assert "ad.local" in a.domains
    assert "wsus.internal" in a.domains
    assert "10.1.2.3" in a.ips
    assert "e7d705a3286e19ea42f587b344ee6865" in a.ja3
    assert a.smb is True


def test_domain_regex_ignores_prose_and_filenames() -> None:
    """Avoid false positives: 'e.g.' and dotted filenames are not domains."""
    a = extract_artifacts("e.g. the report.json file and main.py were unchanged.")
    assert a.domains == []


def test_com_domain_is_extracted_and_flagged() -> None:
    """F03: a fabricated *.com domain — the single most common C2/phishing TLD —
    must be extracted as an artifact and, when ungrounded, flagged. The `.com.`
    stop-suffix used to swallow every .com domain (its own `.rstrip('.')` collided
    with the legitimate TLD), so this whole class evaded the grounding check."""
    from soc_ai.agent.narrative_grounding import _looks_like_domain

    assert _looks_like_domain("evilbeacon.com") is True
    seed = "Alert: ET SCAN (10.0.0.5 → 10.0.0.9)"
    answer = (
        "**This host connected out to evilbeacon.com, a benign CDN endpoint, so "
        "this is a false positive.**"
    )
    a = extract_artifacts(answer)
    assert "evilbeacon.com" in a.domains
    g = check_narrative_grounding(answer, seed_context=seed, tool_evidence=[])
    assert g.grounded is False
    assert "evilbeacon.com" in g.ungrounded


def test_caveat_text_is_marked() -> None:
    """The appended caveat is clearly marked as unverified."""
    assert "Unverified" in UNVERIFIED_CAVEAT
    assert "hypothesis" in UNVERIFIED_CAVEAT


def test_scoped_caveat_names_the_ungrounded_artifacts() -> None:
    """When the turn RAN tools, the blanket 'not backed by a tool result'
    caveat contradicts the visible tool-call footer (dogfood 2026-07-15).
    The scoped variant names the specific suspect claims instead."""
    from soc_ai.agent.narrative_grounding import scoped_unverified_caveat

    caveat = scoped_unverified_caveat(["ad.local", "DESKTOP-JSM4N2P"])
    assert "ad.local" in caveat
    assert "DESKTOP-JSM4N2P" in caveat
    assert "verify" in caveat.lower()
    # It must NOT claim the whole reply lacked tool backing.
    assert "was not backed by a tool result" not in caveat


def test_scoped_caveat_caps_the_artifact_list() -> None:
    from soc_ai.agent.narrative_grounding import scoped_unverified_caveat

    caveat = scoped_unverified_caveat([f"host-{i}.corp" for i in range(10)])
    assert "host-0.corp" in caveat
    assert "host-9.corp" not in caveat  # capped, not an unbounded dump
    assert "…" in caveat
