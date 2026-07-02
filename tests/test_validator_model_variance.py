"""Regression-gate tests for the model-agnostic post-validator chain.

The post-validators must accept citations + outputs from any reasonable
inference model "voice" — Nemotron-style canonical paths, bare
IPs/host.name/free-text, and mixed forms from other models. The validator
must GRADE (continuous coverage score, preserve verdict) rather than GATE
(binary pass/fail, erase verdict).

These tests are the regression gate for future model swaps: any new
model integration MUST pass this suite before flag flip.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

import pytest


class _RetPart:
    """ToolReturnPart-like stand-in: content + the real part_kind discriminator."""

    def __init__(self, content: Any) -> None:
        self.content = content
        self.part_kind = "tool-return"


class _Msg:
    def __init__(self, parts: list[Any]) -> None:
        self.parts = parts


def _tool_evidence() -> list[Any]:
    """A message history with one successful tool return — exempts the hard
    evidence gate so a downstream validator (citation cap / floor / ICMP scope)
    can be unit-tested in isolation. These tests pre-date the gate and assert
    verdict-PRESERVATION given that an investigation already gathered evidence."""
    return [_Msg([_RetPart({"result": "ok"})])]


def _benign_internal_bundle() -> Any:
    """A representative `EnrichedAlertContext`-shaped dump for benign
    internal traffic. Used by all voice variants so we can verify that
    different citation shapes resolve against the SAME prefetch."""
    return MagicMock(
        model_dump=lambda mode="json": {
            "alert": {
                "alert_id": "test-alert-001",
                "source_ip": "10.0.0.42",
                "destination_ip": "10.0.0.1",
                "source_port": 49321,
                "destination_port": 53,
                "rule_name": "ET POLICY DNS Query for .click TLD",
                "rule_metadata": {
                    "signature_severity": "Informational",
                    "malware_family": None,
                },
                "classtype": "policy-violation",
                "alert_action": "allowed",
                "network_community_id": "1:abc123def456=",
            },
            "enrichments": {
                "10.0.0.42": {
                    "internal": True,
                    "blocklist_hits": [],
                    "misp_hits": [],
                    "asn": None,
                },
                "10.0.0.1": {
                    "internal": True,
                    "blocklist_hits": [],
                    "misp_hits": [],
                },
            },
            "typed_zeek": {"conn_states": ["SF"]},
            "community_id_events": [],
            "host_events": [],
        }
    )


def _malicious_bundle() -> Any:
    """A bundle where blocklist + rule_name should justify true_positive."""
    return MagicMock(
        model_dump=lambda mode="json": {
            "alert": {
                "alert_id": "test-alert-002",
                "source_ip": "10.0.0.42",
                "destination_ip": "185.220.101.7",
                "source_port": 49321,
                "destination_port": 443,
                "rule_name": "ETPRO TROJAN Win32/Emotet CnC Activity (POST)",
                "rule_metadata": {
                    "signature_severity": "Major",
                    "malware_family": "Emotet",
                },
                "classtype": "trojan-activity",
                "alert_action": "allowed",
                "network_community_id": "1:emotet-flow-hash=",
            },
            "enrichments": {
                "185.220.101.7": {
                    "internal": False,
                    "blocklist_hits": [{"source": "Feodo Tracker", "tags": ["emotet", "c2"]}],
                    "misp_hits": [],
                    "asn": {"org": "Hosting Provider"},
                },
            },
            "typed_zeek": {"conn_states": ["SF"]},
            "community_id_events": [],
            "host_events": [],
        }
    )


class TestSemanticCitationResolution:
    """`_resolve_citations` must accept varied citation shapes from any
    model voice and return a continuous `coverage_ratio`."""

    def test_canonical_path_form_resolves(self) -> None:
        """Nemotron-voice: dotted paths like `alert.rule_metadata.signature_severity`."""
        from soc_ai.agent.orchestrator import _resolve_citations

        ctx = _benign_internal_bundle()
        result = _resolve_citations(
            ["alert.rule_metadata.signature_severity", "alert.alert_action"],
            ctx,
            transcripts=[],
        )
        assert result["coverage_ratio"] == 1.0
        assert all(p["resolved"] for p in result["per_citation"])

    def test_bare_ip_resolves(self) -> None:
        """Bare-token voice: bare IP appears in `alert.source_ip` so it should resolve."""
        from soc_ai.agent.orchestrator import _resolve_citations

        ctx = _benign_internal_bundle()
        result = _resolve_citations(
            ["10.0.0.42", "10.0.0.1"],
            ctx,
            transcripts=[],
        )
        assert result["coverage_ratio"] == 1.0

    def test_keyvalue_form_resolves_when_value_in_bundle(self) -> None:
        """Key-value voice: `host.name=foo` style — at least one substantive token must match."""
        from soc_ai.agent.orchestrator import _resolve_citations

        ctx = _malicious_bundle()
        result = _resolve_citations(
            ["malware_family=Emotet", "signature_severity=Major"],
            ctx,
            transcripts=[],
        )
        assert result["coverage_ratio"] == 1.0

    def test_freetext_quote_resolves_via_substring(self) -> None:
        """Free-text voice: free-text citations matching rule.name etc."""
        from soc_ai.agent.orchestrator import _resolve_citations

        ctx = _malicious_bundle()
        result = _resolve_citations(
            ["ET TROJAN", "Emotet CnC", "Feodo Tracker"],
            ctx,
            transcripts=[],
        )
        assert result["coverage_ratio"] == 1.0

    def test_community_id_form_resolves(self) -> None:
        """Bare community_id: `1:abc123def456=` is a substantive token in the bundle."""
        from soc_ai.agent.orchestrator import _resolve_citations

        ctx = _benign_internal_bundle()
        result = _resolve_citations(
            ["1:abc123def456=", "community_id:1:abc123def456="],
            ctx,
            transcripts=[],
        )
        assert result["coverage_ratio"] == 1.0

    def test_unresolvable_citation_lowers_coverage(self) -> None:
        """A citation whose substantive tokens don't appear in the bundle
        → not resolved → coverage < 1.

        Phrase form (with spaces) is used so it doesn't auto-classify as a
        plain-id (which the legacy classifier auto-trusts).
        """
        from soc_ai.agent.orchestrator import _resolve_citations

        ctx = _benign_internal_bundle()
        result = _resolve_citations(
            ["alert.rule_metadata.signature_severity", "Atlantis pony unicorn 7777"],
            ctx,
            transcripts=[],
        )
        assert result["coverage_ratio"] == 0.5
        unresolved = [p for p in result["per_citation"] if not p["resolved"]]
        assert len(unresolved) == 1
        assert "Atlantis" in unresolved[0]["citation"]

    def test_empty_citations_returns_full_coverage(self) -> None:
        """Vacuous-truth: no citations → no missing evidence to penalize → coverage=1."""
        from soc_ai.agent.orchestrator import _resolve_citations

        ctx = _benign_internal_bundle()
        result = _resolve_citations([], ctx, transcripts=[])
        assert result["coverage_ratio"] == 1.0
        assert result["total"] == 0

    def test_short_token_does_not_falsely_resolve(self) -> None:
        """Very short citations (<3 chars of substantive token) must NOT
        falsely resolve via accidental substring match."""
        from soc_ai.agent.orchestrator import _resolve_citations

        ctx = _benign_internal_bundle()
        result = _resolve_citations(["x", "a"], ctx, transcripts=[])
        assert result["coverage_ratio"] == 0.0


class TestBandedConfidenceCap:
    """`_citation_confidence_cap` must use banded penalties, never zero out."""

    def test_full_coverage_no_penalty(self) -> None:
        from soc_ai.agent.orchestrator import _citation_confidence_cap

        # 1.0 coverage → multiplier 1.0
        capped = _citation_confidence_cap(0.85, coverage_ratio=1.0)
        assert capped == pytest.approx(0.85)

    def test_half_coverage_applies_band(self) -> None:
        """Coverage 0.5 → band ≥0.5 → multiplier 0.9 → 0.85 * 0.9 = 0.765."""
        from soc_ai.agent.orchestrator import _citation_confidence_cap

        capped = _citation_confidence_cap(0.85, coverage_ratio=0.5)
        assert capped == pytest.approx(0.85 * 0.9)

    def test_low_coverage_applies_band(self) -> None:
        """Coverage 0.2 → band <0.25 → multiplier 0.5 → never zero."""
        from soc_ai.agent.orchestrator import _citation_confidence_cap

        capped = _citation_confidence_cap(0.85, coverage_ratio=0.2)
        assert capped == pytest.approx(0.85 * 0.5)
        # NEVER zero — this is the key contract change.
        assert capped > 0.0

    def test_zero_coverage_still_above_floor(self) -> None:
        """coverage_ratio=0.0 still must NOT zero confidence — floor it at 0.4."""
        from soc_ai.agent.orchestrator import _citation_confidence_cap

        capped = _citation_confidence_cap(0.85, coverage_ratio=0.0)
        # band <0.25 multiplier is 0.5; 0.85*0.5 = 0.425. Above 0.4 floor.
        assert capped >= 0.4
        assert capped == pytest.approx(0.85 * 0.5)

    def test_zero_coverage_floored_when_starting_low(self) -> None:
        """confidence=0.5, coverage=0.0 → 0.5*0.5 = 0.25, but floor=0.4."""
        from soc_ai.agent.orchestrator import _citation_confidence_cap

        capped = _citation_confidence_cap(0.5, coverage_ratio=0.0)
        assert capped == pytest.approx(0.4)  # floored

    def test_band_boundary_values(self) -> None:
        """Boundaries at 0.75 / 0.5 / 0.25 use the higher band (inclusive)."""
        from soc_ai.agent.orchestrator import _citation_confidence_cap

        # 0.75 → band ≥0.75 → 1.0x
        assert _citation_confidence_cap(0.8, coverage_ratio=0.75) == pytest.approx(0.8)
        # 0.50 → band ≥0.5 → 0.9x
        assert _citation_confidence_cap(0.8, coverage_ratio=0.5) == pytest.approx(0.72)
        # 0.25 → band ≥0.25 → 0.75x
        assert _citation_confidence_cap(0.8, coverage_ratio=0.25) == pytest.approx(0.6)


class TestEvidenceConditionalFloor:
    """`_synth_first_post_validate` must NOT coerce verdict to NMI just
    because citation shape is malformed — only when evidence is missing."""

    def _make_triage(
        self,
        verdict: str = "false_positive",
        confidence: float = 0.85,
        citations: list[str] | None = None,
    ) -> Any:
        from soc_ai.agent.triage import TriageReport

        default_cites = ["alert.rule_metadata.signature_severity"]
        return TriageReport(
            verdict=verdict,  # type: ignore[arg-type]
            confidence=confidence,
            summary="test summary",
            citations=citations if citations is not None else default_cites,
            recommended_actions=[],
            gap_for_investigator=None,
        )

    def test_verdict_preserved_when_citations_partially_resolve(self) -> None:
        """Even if half citations are shape-malformed but other half resolve,
        the verdict LABEL must survive — only confidence shaves."""
        from soc_ai.agent.orchestrator import _synth_first_post_validate

        ctx = _benign_internal_bundle()
        report = self._make_triage(
            verdict="false_positive",
            confidence=0.85,
            citations=["alert.rule_metadata.signature_severity", "FabricatedThing9999"],
        )
        validated, _ = _synth_first_post_validate(
            report,
            ctx,
            candidate=None,
            targeted_messages=_tool_evidence(),
            targeted_tool_called=None,
            synthesis_confidence_floor=0.6,
        )
        # Verdict label preserved.
        assert validated.verdict == "false_positive"
        # Confidence shaved by the band, NOT zeroed.
        assert validated.confidence > 0.4

    def test_verdict_coerced_only_when_zero_citations(self) -> None:
        """When citations list is empty AND confidence < floor, THEN coerce."""
        from soc_ai.agent.orchestrator import _synth_first_post_validate

        ctx = _benign_internal_bundle()
        report = self._make_triage(
            verdict="false_positive",
            confidence=0.3,  # already below floor
            citations=[],
        )
        validated, _ = _synth_first_post_validate(
            report,
            ctx,
            candidate=None,
            targeted_messages=None,
            targeted_tool_called=None,
            synthesis_confidence_floor=0.6,
        )
        # Zero citations + low confidence → coerce to NMI.
        assert validated.verdict == "needs_more_info"

    def test_verdict_preserved_when_citations_resolve_even_if_conf_below_floor(self) -> None:
        """Banded cap may drop confidence below 0.6 floor — but if citations
        semantically resolve, KEEP the verdict label."""
        from soc_ai.agent.orchestrator import _synth_first_post_validate

        ctx = _benign_internal_bundle()
        # Confidence starts at 0.5; coverage=1.0 → no cap → final 0.5 (below 0.6 floor)
        report = self._make_triage(
            verdict="false_positive",
            confidence=0.5,
            citations=["alert.rule_metadata.signature_severity"],
        )
        validated, _ = _synth_first_post_validate(
            report,
            ctx,
            candidate=None,
            targeted_messages=_tool_evidence(),
            targeted_tool_called=None,
            synthesis_confidence_floor=0.6,
        )
        # Verdict preserved — citations resolved, low confidence is OK.
        assert validated.verdict == "false_positive"


class TestModelVoiceVariance:
    """Three model voices producing the SAME logical verdict via DIFFERENT
    citation shapes must end up with the same verdict label and within ±10%
    confidence after post-validation."""

    def _make_triage(self, citations: list[str]) -> Any:
        from soc_ai.agent.triage import TriageReport

        return TriageReport(
            verdict="false_positive",  # type: ignore[arg-type]
            confidence=0.85,
            summary="Benign internal DNS query.",
            citations=citations,
            recommended_actions=[],
            gap_for_investigator=None,
        )

    def _validate(self, report: Any, ctx: Any) -> Any:
        from soc_ai.agent.orchestrator import _synth_first_post_validate

        validated, _ = _synth_first_post_validate(
            report,
            ctx,
            candidate=None,
            targeted_messages=_tool_evidence(),
            targeted_tool_called=None,
            synthesis_confidence_floor=0.6,
        )
        return validated

    def test_three_voices_converge_on_benign(self) -> None:
        ctx = _benign_internal_bundle()
        # Nemotron-voice: canonical dotted paths
        v1 = self._validate(
            self._make_triage(
                [
                    "alert.rule_metadata.signature_severity",
                    "alert.alert_action",
                    "alert.classtype",
                ]
            ),
            ctx,
        )
        # Bare-token voice: bare IPs / key=value / community_id
        v2 = self._validate(
            self._make_triage(
                [
                    "10.0.0.42",
                    "alert_action=allowed",
                    "1:abc123def456=",
                ]
            ),
            ctx,
        )
        # Free-text voice: free-text quotes + identifiers
        v3 = self._validate(
            self._make_triage(
                [
                    "Informational",
                    "policy-violation",
                    "test-alert-001",
                ]
            ),
            ctx,
        )
        # All three converge on FP.
        assert v1.verdict == "false_positive"
        assert v2.verdict == "false_positive"
        assert v3.verdict == "false_positive"
        # Confidences within ±10% of each other.
        confs = [v1.confidence, v2.confidence, v3.confidence]
        assert max(confs) - min(confs) <= 0.10, f"voice variance exceeded ±10%: {confs}"

    def test_three_voices_converge_on_malicious(self) -> None:
        ctx = _malicious_bundle()

        def _make_tp(citations: list[str]) -> Any:
            from soc_ai.agent.triage import TriageReport

            return TriageReport(
                verdict="true_positive",  # type: ignore[arg-type]
                confidence=0.85,
                summary="Emotet C2 callback confirmed.",
                citations=citations,
                recommended_actions=[],
                gap_for_investigator=None,
            )

        v1 = self._validate(
            _make_tp(
                [
                    "alert.rule_metadata.malware_family",
                    "enrichments.185.220.101.7.blocklist_hits",
                    "alert.classtype",
                ]
            ),
            ctx,
        )
        v2 = self._validate(
            _make_tp(
                [
                    "185.220.101.7",
                    "Emotet",
                    "Feodo Tracker",
                ]
            ),
            ctx,
        )
        v3 = self._validate(
            _make_tp(
                [
                    "ETPRO TROJAN",
                    "trojan-activity",
                    "malware_family=Emotet",
                ]
            ),
            ctx,
        )

        assert v1.verdict == "true_positive"
        assert v2.verdict == "true_positive"
        assert v3.verdict == "true_positive"
        confs = [v1.confidence, v2.confidence, v3.confidence]
        assert max(confs) - min(confs) <= 0.10, f"voice variance: {confs}"


class TestPhaseDDispatchLenience:
    """Phase D must drop hallucinated tool kwargs and retry
    instead of fail-stopping. Some reasoning models emit hallucinated
    kwargs (e.g. ``'社区ID'``, ``'filter'``, ``'dataset'`` — none of which
    any real tool accepts)."""

    @pytest.mark.asyncio
    async def test_unknown_kwarg_dropped_and_retried(self) -> None:
        """Hallucinated kwarg `extra_kwarg` is dropped, retry succeeds."""
        from unittest.mock import patch

        from soc_ai.agent.targeted_investigator import run_targeted_investigation
        from soc_ai.agent.triage import TargetedGap

        calls: list[dict[str, Any]] = []

        async def stub_enrich_ip(
            ip: str,
            *,
            settings: Any,
            misp: Any = None,
            blocklist: Any = None,
            maxmind: Any = None,
            cloud: Any = None,
        ) -> dict[str, Any]:
            calls.append({"ip": ip})
            return {"ip": ip, "result": "enriched"}

        ctx = MagicMock(settings=MagicMock(), misp=None, blocklist=None, maxmind=None, cloud=None)
        gap = TargetedGap(
            question="enrich the IP",
            tool_name="t_enrich_ip",
            tool_args={"ip": "8.8.8.8", "extra_kwarg": "hallucinated"},
            why_this_matters="test",
        )
        with patch("soc_ai.tools.enrichment.enrich_ip", stub_enrich_ip):
            result = await run_targeted_investigation(gap, ctx=ctx)
        assert result == {"ip": "8.8.8.8", "result": "enriched"}
        # Retry was the only successful call (first one raised TypeError).
        assert len(calls) == 1

    @pytest.mark.asyncio
    async def test_genuine_typerror_still_surfaces(self) -> None:
        """If the TypeError is not from an unknown kwarg (e.g. missing
        required positional, wrong type), the dispatch still fails
        gracefully via run_targeted_investigation's outer except."""
        from unittest.mock import patch

        from soc_ai.agent.targeted_investigator import run_targeted_investigation
        from soc_ai.agent.triage import TargetedGap

        async def stub_enrich_ip(
            ip: str,
            *,
            settings: Any,
            misp: Any = None,
            blocklist: Any = None,
            maxmind: Any = None,
            cloud: Any = None,
        ) -> dict[str, Any]:
            # Simulate a tool that genuinely raises TypeError for a wrong-type arg.
            raise TypeError("ip must be a string IPv4 address, got 12345")

        ctx = MagicMock(settings=MagicMock(), misp=None, blocklist=None, maxmind=None, cloud=None)
        gap = TargetedGap(
            question="enrich the IP",
            tool_name="t_enrich_ip",
            tool_args={"ip": "8.8.8.8"},  # no hallucinated kwargs
            why_this_matters="test",
        )
        with patch("soc_ai.tools.enrichment.enrich_ip", stub_enrich_ip):
            result = await run_targeted_investigation(gap, ctx=ctx)
        # No kwargs to drop → re-raises → outer except formats as error string.
        assert isinstance(result, str)
        assert "TypeError" in result
        assert "must be a string IPv4" in result


def _icmp_bundle(
    *, dst_internal: bool = True, blocklist: bool = False, icmp_echo: bool = True
) -> Any:
    """EnrichedAlertContext-shaped dump for an ICMP alert, parameterized for
    the solicited-echo-reply downgrade gate."""
    dst_ip = "10.20.30.15" if dst_internal else "8.8.8.8"
    dst_enr = {
        "internal": dst_internal,
        "blocklist_hits": ([{"source": "Feodo Tracker", "tags": ["x"]}] if blocklist else []),
        "misp_hits": [],
    }
    return MagicMock(
        model_dump=lambda mode="json": {
            "alert": {
                "alert_id": "bpfdoor-icmp-001",
                "source_ip": "10.20.30.1",
                "destination_ip": dst_ip,
                "rule_name": "ET MALWARE BPFDoor ICMP Echo Reply, Heartbeat (Outbound)",
                "rule_metadata": {"signature_severity": "Major", "malware_family": "BPFDoor"},
                "classtype": "trojan-activity",
                "network_community_id": "1:CSbkGEIzlqsf6hunF8j9ArPlGwA=",
            },
            "enrichments": {
                "10.20.30.1": {"internal": True, "blocklist_hits": [], "misp_hits": []},
                dst_ip: dst_enr,
            },
            "typed_zeek": {"conn_states": ["OTH"], "icmp_echo_request_reply": icmp_echo},
            "community_id_events": [],
            "host_events": [],
        }
    )


class TestSolicitedIcmpEchoDowngrade:
    """A true_positive resting on a solicited internal ICMP echo
    reply (a ping response — Zeek type-8 request → type-0 reply, both RFC1918,
    no IOC) is a noisy-signature false escalation, not C2. Downgrade to
    false_positive. Scoped to ICMP echo so it cannot regress internal
    lateral-movement TPs (SMB/Kerberos)."""

    def _make_tp(self) -> Any:
        from soc_ai.agent.triage import TriageReport

        return TriageReport(
            verdict="true_positive",  # type: ignore[arg-type]
            confidence=0.85,
            summary="BPFDoor ICMP heartbeat — symmetric byte counts indicate C2 tunnel.",
            citations=["bpfdoor-icmp-001", "alert.classtype"],
            recommended_actions=[],
            gap_for_investigator=None,
        )

    def _validate(self, report: Any, ctx: Any) -> Any:
        from soc_ai.agent.orchestrator import _synth_first_post_validate

        validated, _audit = _synth_first_post_validate(
            report,
            ctx,
            candidate=None,
            targeted_messages=_tool_evidence(),
            targeted_tool_called=None,
            synthesis_confidence_floor=0.6,
        )
        return validated

    def test_solicited_internal_icmp_echo_tp_downgraded_to_fp(self) -> None:
        v = self._validate(self._make_tp(), _icmp_bundle())
        assert v.verdict == "false_positive"
        assert v.recommended_actions == []

    def test_downgrade_reconciles_summary(self) -> None:
        """When the verdict is downgraded, the summary must lead
        with the correct FP/benign conclusion — no confusing inline bracket.
        The agent's original text is preserved in validator_note, not prepended
        to the summary."""
        original = self._make_tp()
        v = self._validate(original, _icmp_bundle())
        # Summary must NOT start with the old bracket — leads with the correct conclusion.
        assert not v.summary.lower().startswith("[auto-corrected")
        assert "solicited" in v.summary.lower()
        # Original synth narrative relocated to validator_note.
        assert "symmetric byte counts" not in v.summary
        assert v.validator_note is not None
        assert "symmetric byte counts" in v.validator_note
        assert "true_positive" in v.validator_note  # records what was overridden

    def test_external_dest_icmp_echo_not_downgraded(self) -> None:
        """Solicited echo reply to an EXTERNAL dest could be ICMP exfil — keep TP."""
        v = self._validate(self._make_tp(), _icmp_bundle(dst_internal=False))
        assert v.verdict == "true_positive"

    def test_blocklist_hit_icmp_echo_not_downgraded(self) -> None:
        """A real IOC hit on the flow overrides the benign-ping heuristic."""
        v = self._validate(self._make_tp(), _icmp_bundle(blocklist=True))
        assert v.verdict == "true_positive"

    def test_non_icmp_echo_internal_tp_not_downgraded(self) -> None:
        """Internal→internal WITHOUT a solicited ICMP echo (e.g. SMB lateral
        movement) must NOT be downgraded — protects h2-PsExec / h1-Kerberoasting."""
        v = self._validate(self._make_tp(), _icmp_bundle(icmp_echo=False))
        assert v.verdict == "true_positive"

    def test_already_false_positive_unchanged(self) -> None:
        from soc_ai.agent.triage import TriageReport

        fp = TriageReport(
            verdict="false_positive",  # type: ignore[arg-type]
            confidence=0.85,
            summary="benign ping",
            citations=["bpfdoor-icmp-001"],
            recommended_actions=[],
            gap_for_investigator=None,
        )
        v = self._validate(fp, _icmp_bundle())
        assert v.verdict == "false_positive"
