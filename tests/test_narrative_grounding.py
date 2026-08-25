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
    UNVERIFIED_QUIET_LINE,
    check_narrative_grounding,
    extract_artifacts,
    redact_ungrounded,
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


def test_lowercase_hostname_needs_backticks_to_qualify() -> None:
    """F21 (historical): a fabricated hostname written in lowercase evaded
    detection purely by capitalization, because `_HOSTNAME` was case-
    sensitive — fixed by making the regex itself case-insensitive, so it still
    FINDS a lowercase-shaped candidate like `desktop-jsm4n2p`. What counts as
    a QUALIFYING artifact has narrowed twice since, and this case moved
    between the two rulings: 2026-08-20 required a digit, an uppercase
    letter, or backticks (a digit alone was enough, so this qualified);
    2026-08-21 tightened it to NetBIOS-shaped (no lowercase letter ANYWHERE)
    or backticks, because "C2-style" has a digit too. Unformatted, this is
    now the accepted tradeoff (test_plain_prose_lowercase_hostname_is_the_
    accepted_tradeoff) — code-formatting it is what still gets it caught."""
    seed = "Alert: ET SCAN (10.0.0.5 → 10.0.0.9)"
    unformatted = (
        "**The traffic originated from workstation desktop-jsm4n2p per our "
        "inventory, so this is benign.**"
    )
    assert extract_artifacts(unformatted).hostnames == []
    g = check_narrative_grounding(unformatted, seed_context=seed, tool_evidence=[])
    assert g.grounded is True

    backticked = unformatted.replace("desktop-jsm4n2p", "`desktop-jsm4n2p`")
    assert "desktop-jsm4n2p" in extract_artifacts(backticked).hostnames
    g2 = check_narrative_grounding(backticked, seed_context=seed, tool_evidence=[])
    assert g2.grounded is False
    assert "desktop-jsm4n2p" in g2.ungrounded


def test_lowercase_hyphenated_prose_is_not_extracted_as_a_hostname() -> None:
    """2026-08-20 dogfood: asking the dashboard chat "what's going on with
    192.0.2.61" during a benign duplicate-IP dig came back with a caveat banner
    listing `closest-preceding`, `malicious-external`, `origin-chain`,
    `package-update` — ordinary hyphenated English compounds from the model's
    own prose, not hostnames. The old hostname regex matched ANY hyphen-joined
    alnum pair case-insensitively, so plain lowercase prose was
    indistinguishable from a NetBIOS-style host label."""
    sentences = [
        "The closest-preceding event on this host was a routine DHCP renewal.",
        "Nothing here points to a malicious-external actor; the traffic stayed internal.",
        "Tracing the origin-chain back, the flow starts at the gateway.",
        "This looks like a routine package-update pulling signatures from the mirror.",
    ]
    for sentence in sentences:
        a = extract_artifacts(sentence)
        assert a.hostnames == [], f"{sentence!r} should not extract a hostname, got {a.hostnames}"


def test_2026_08_21_incident_prose_tokens_are_not_extracted() -> None:
    """Live incident (2026-08-21): a chat turn answering "what is going on
    with 192.0.2.61?" used ordinary security prose — 'C2-like', 'C2-style',
    'Origin-chain', 'Tor-check', 'Cloudflare-fronted' — that the prior
    "digit-or-uppercase-anywhere" qualifier mistook for unverified hostnames
    (an initial capital, or for the C2 tokens a digit, was enough). The turn
    burned BOTH of its regrounding attempts chasing these before the terminal
    check flagged 'C2-style' and 'Cloudflare-fronted' again and redacted them
    out of an otherwise-good, fully-cited answer. None of the five should ever
    have qualified: every one has a lowercase letter somewhere and none is
    backticked."""
    sentences = [
        "The traffic pattern doesn't look C2-like at all.",
        "Nothing here reads as C2-style beaconing.",
        "Tracing the Origin-chain back, the flow starts at the gateway.",
        "A Tor-check against the destination came back negative.",
        "The destination is Cloudflare-fronted, which explains the shared IP.",
    ]
    for sentence in sentences:
        a = extract_artifacts(sentence)
        assert a.hostnames == [], f"{sentence!r} should not extract a hostname, got {a.hostnames}"


def test_all_caps_digit_or_backticked_hyphenated_tokens_still_extract() -> None:
    """The 2026-08-21 tightened matcher keeps the two shapes a real fabricated
    hostname reliably takes: fully NetBIOS-shaped — every character uppercase
    or a digit, no lowercase anywhere — or explicitly code-formatted
    (backticked). A digit or an uppercase letter ANYWHERE in an otherwise-
    lowercase token is no longer enough on its own (that was the 2026-08-20
    rule; ordinary security prose — "C2-style", "Origin-chain" — has exactly
    that shape too)."""
    assert "DESKTOP-JSM4N2P" in extract_artifacts("Host DESKTOP-JSM4N2P answered.").hostnames
    assert "WIN-AB12CD" in extract_artifacts("Talked to WIN-AB12CD next.").hostnames
    assert "mail-server" in extract_artifacts("It queried `mail-server` for MX records.").hostnames


def test_plain_prose_lowercase_hostname_is_the_accepted_tradeoff() -> None:
    """Owner-ratified tradeoff, narrowed twice. 2026-08-20: an unformatted,
    all-lowercase, DIGIT-FREE hostname (e.g. `mail-server`) stopped
    qualifying. 2026-08-21: a lowercase hostname that DOES contain a digit
    (e.g. `desktop-jsm4n2p`) stopped qualifying too — alnum-with-a-digit is
    indistinguishable from prose like "C2-style". False negatives on a rare
    unformatted real hostname beat flagging ordinary hyphenated security
    vocabulary as "unverified hostnames", which is what burned both of a live
    turn's regrounding attempts on 2026-08-21. Code-formatting (backticks)
    remains the escape hatch for a genuine unformatted name."""
    assert extract_artifacts("It queried mail-server for MX records.").hostnames == []
    assert extract_artifacts("Traffic came from desktop-jsm4n2p again.").hostnames == []


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


def test_domain_regex_scales_linearly_on_dot_dense_text() -> None:
    """``_DOMAIN`` must not backtrack super-linearly on dot-dense text.

    A model answer can echo a payload_printable / DNS-heavy blob into the
    narrative; ``extract_artifacts`` runs on the event loop inside the bounded
    regrounding retry loop, so quadratic cost multiplies per attempt.

    Asserts SCALING, not wall-clock — a stopwatch bound measures the machine and
    flakes under CPU contention (the class this repo has been burned by).
    Doubling the input is the load-invariant discriminator: backtracking is
    super-linear (quadratic gives ~4x) while a bounded pattern is linear (~2x),
    and both measurements slow together under load so their ratio holds.
    """
    import time

    from soc_ai.agent.narrative_grounding import _DOMAIN

    def build(n: int) -> str:
        return "a." * n + "a" * 100  # dot-dense label run with no valid TLD tail

    def elapsed(payload: str) -> float:
        start = time.perf_counter()
        list(_DOMAIN.finditer(payload))
        return time.perf_counter() - start

    elapsed("ab" * 100)  # warm the compiled pattern before anything is timed
    single = elapsed(build(10_000))
    double = elapsed(build(20_000))
    scaling = double / max(single, 1e-6)
    assert scaling < 3.0, f"ReDoS: _DOMAIN scaled {scaling:.2f}x on 2x input (linear is 2.0)"


def test_domain_regex_matching_semantics_preserved() -> None:
    """The linear rewrite matches exactly what the old pattern did: the same
    domains still surface as artifacts, the same non-domains still don't."""

    def domains(text: str) -> list[str]:
        return extract_artifacts(text).domains

    # Real domains still match (single/multi-label, hyphens, mixed case, wildcard).
    assert domains("resolved ad.local and wsus.internal") == ["ad.local", "wsus.internal"]
    assert domains("beacon to foo.corp.example.com now") == ["foo.corp.example.com"]
    assert domains("hyphen-name.example.co.uk here") == ["hyphen-name.example.co.uk"]
    assert domains("MixedCase.Example.COM domain") == ["MixedCase.Example.COM"]
    assert domains("wildcard *.example.com cert") == ["example.com"]
    # Non-domains still don't (prose fragments, dotted filenames, field paths, IPs).
    assert domains("e.g. the report.json and main.py were unchanged") == []
    assert domains("queried zeek.dns and event.dataset fields") == []
    assert domains("connected to 192.168.1.1 only") == []


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


def test_quiet_line_names_no_tokens_and_carries_no_alarm_glyph() -> None:
    """Ground-or-strip (2026-08-20): the terminal fallback for an ungrounded
    claim is no longer a caveat banner naming the suspect tokens — a 2026-08-20
    dogfood turn shipped exactly such a banner listing ordinary prose fragments
    ("closest-preceding", "package-update") as "unverified hostnames". The
    replacement line says something was removed, once, with no token list and
    no ⚠."""
    assert "unverifiable" in UNVERIFIED_QUIET_LINE.lower()
    assert "removed" in UNVERIFIED_QUIET_LINE.lower()
    assert "⚠" not in UNVERIFIED_QUIET_LINE


def test_redact_ungrounded_replaces_every_occurrence_case_insensitively() -> None:
    """The old scoped caveat NAMED the suspect claims inline; redaction REMOVES
    them from the visible answer instead — whole-token, case-insensitive, every
    occurrence, so a claim repeated in a different case still comes out."""
    answer = "The host DESKTOP-JSM4N2P resolved ad.local; desktop-jsm4n2p asked again."
    redacted = redact_ungrounded(answer, ["ad.local", "DESKTOP-JSM4N2P"])
    assert "ad.local" not in redacted.lower()
    assert "desktop-jsm4n2p" not in redacted.lower()
    assert redacted.count("(unverified)") == 3  # both DESKTOP-JSM4N2P spellings + ad.local


def test_redact_ungrounded_leaves_grounded_text_untouched() -> None:
    """Redaction is scoped to the ungrounded list — a grounded artifact sitting
    right next to a fabricated one in the same sentence must survive."""
    answer = "WIN11-LAB01 (grounded) resolved ad.local (not grounded)."
    redacted = redact_ungrounded(answer, ["ad.local"])
    assert "WIN11-LAB01" in redacted
    assert "ad.local" not in redacted


def test_redact_ungrounded_collapses_a_prefix_overlap_with_no_dangling_suffix() -> None:
    """A shorter ungrounded artifact that is a PREFIX of a longer one (a bare
    IP vs. the same IP with a port) must not partially clobber the longer
    replacement — longest-first order is what keeps `192.0.2.61:443` from
    leaving a dangling `:443` once `192.0.2.61` alone would otherwise match
    first and eat only its own five characters."""
    answer = "Beaconed to 192.0.2.61:443, and separately 192.0.2.61 answered on 80."
    redacted = redact_ungrounded(answer, ["192.0.2.61", "192.0.2.61:443"])
    assert ":443" not in redacted
    assert "192.0.2.61" not in redacted
    assert redacted.count("(unverified)") == 2


def test_redact_ungrounded_caps_nothing_and_names_nothing() -> None:
    """Unlike the old scoped caveat (capped at 4, "…" for the rest), redaction
    has no cap to get wrong — every ungrounded artifact is a text replacement,
    not a line in a list that has to fit."""
    ungrounded = [f"host-{i}.corp" for i in range(10)]
    redacted = redact_ungrounded(" ".join(ungrounded), ungrounded)
    assert "host-0.corp" not in redacted
    assert "host-9.corp" not in redacted
    assert redacted.count("(unverified)") == 10
