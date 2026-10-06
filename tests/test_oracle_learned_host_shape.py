"""A host name learned from free text must look like a host name.

The egress guard learns internal host names from free text: a UNC path, a
logon name, an account domain, a NetBIOS name, a configured host name. The
learned set is then searched for everywhere in the payload, and a hit refuses
the whole escalation. After the credential shape rule of 2026-09-18, four of
the nineteen stored refusals still refused with today's code. Each shape is
replayed here, anonymised:

1. a 2-letter token learned from a UNC path in an ICMP payload dump,
2. a 2-letter token learned as the domain of a logon-shaped string,
3. a UNC-shaped junk string with a run of dots in an ICMP message,
4. a configured internal host name that is a common English word, also
   present in a public search result URL.

A name that fails the shape rule is labelled where it stands and never joins
the learned set. A name that passes keeps the old behaviour, and its refusal
reason names the rule and the field it was learned from.
"""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

from pydantic import SecretStr
from soc_ai.agent.egress_guard import EgressGuard
from soc_ai.config import Settings
from soc_ai.oracle._cred_data import COMMON_ENGLISH_WORDS, plausible_learned_host
from soc_ai.oracle.client import adjudicate
from soc_ai.oracle.redact import Mapping
from soc_ai.so_client.models import SoAlert
from soc_ai.tools.get_alert_context import EnrichedAlertContext
from soc_ai.triage_models import TriageReport

SUFFIXES = (".corp.example.test",)

VERDICT = json.dumps(
    {"verdict": "false_positive", "confidence": 0.8, "summary": "Benign.", "reasoning": "Ok."}
)


def _settings() -> Settings:
    return Settings(
        so_host="https://so.example.com",
        so_username="analyst",
        so_password=SecretStr("password123"),
        so_verify_ssl=False,
        es_hosts=["https://so.example.com:9200"],
        litellm_base_url="http://gateway.example.test:4000",
        oracle_enabled=True,
        oracle_model="claude-sonnet-4-6",
    )


def _enriched(*, payload_printable: str = "", message: str = "") -> EnrichedAlertContext:
    return EnrichedAlertContext(
        alert=SoAlert(
            id="alert-icmp-1",
            severity_label="medium",
            rule_name="ET MALWARE Test ICMP Heartbeat",
            payload_printable=payload_printable or None,
            message=message or None,
        ),
        pivot_summary={"community_id": 0, "host": 0, "user": 0, "process": 0, "file": 0},
    )


def _tool_messages(result: dict[str, Any], tool: str = "t_web_search") -> list[Any]:
    part = MagicMock(part_kind="tool-return", tool_name=tool, content=result)
    return [MagicMock(parts=[part])]


async def _adjudicate(
    enriched: EnrichedAlertContext,
    *,
    extra_hosts: tuple[str, ...] = (),
    loop_messages: list[Any] | None = None,
) -> tuple[Any, dict[str, Any], AsyncMock]:
    ctx = MagicMock()
    ctx.settings = _settings()
    raw_call = AsyncMock(return_value=VERDICT)
    failure: dict[str, Any] = {}
    with patch("soc_ai.oracle.client._call_oracle_raw", raw_call):
        result = await adjudicate(
            ctx,
            enriched=enriched,
            local_report=TriageReport(
                verdict="false_positive",
                confidence=0.72,
                summary="Local.",
                citations=[],
                recommended_actions=[],
            ),
            transcript_text="",
            loop_messages=loop_messages,
            extra_hosts=extra_hosts,
            extra_suffixes=SUFFIXES,
            failure_out=failure,
        )
    return result, failure, raw_call


# ── The four stored shapes ───────────────────────────────────────────────────


async def test_a_two_letter_unc_host_in_a_payload_dump_no_longer_refuses() -> None:
    """Shape 1. The UNC rule learned ``TP``; the rule tally's ``"tp"`` key refused."""
    enriched = _enriched(payload_printable="..vD;.1...*....3...U..F...mX...a.:\\\\TP\\xY.....")
    noisy_rule = {"rule_name": "ET MALWARE Test ICMP Heartbeat", "fp": 9, "tp": 0, "nmi": 1}
    result, failure, raw_call = await _adjudicate(
        enriched, loop_messages=_tool_messages(noisy_rule, tool="t_rule_noisiness")
    )
    assert failure == {}
    assert result is not None
    raw_call.assert_awaited_once()
    # The UNC host itself is still labelled where it stands.
    sent = raw_call.await_args.args[0]
    assert "\\\\\\\\TP\\\\" not in sent


async def test_a_two_letter_logon_domain_in_a_payload_dump_no_longer_refuses() -> None:
    """Shape 2. ``zq\\Ab9xyz`` read as a logon name; a bare ``zq`` refused."""
    enriched = _enriched(
        payload_printable="....;A.A!zq\\Ab9xyz ^a..>.]",
        message="ICMP echo reply zq from the beacon",
    )
    result, failure, raw_call = await _adjudicate(enriched)
    assert failure == {}
    assert result is not None
    raw_call.assert_awaited_once()


async def test_a_unc_shaped_junk_string_no_longer_refuses() -> None:
    """Shape 3. A run of printables with two dots in a row is no host."""
    enriched = _enriched(message="..{9....\\a..'AB.c..}..9\\\\qR..s..7\\x....")
    result, failure, raw_call = await _adjudicate(enriched)
    assert failure == {}
    assert result is not None
    raw_call.assert_awaited_once()


async def test_a_common_word_host_in_a_search_result_url_no_longer_refuses() -> None:
    """Shape 4. A detected host named like a common word, in a public URL path."""
    assert "garden" in COMMON_ENGLISH_WORDS
    search = {
        "result_count": 1,
        "results": [
            {
                "title": "Garden tips for spring",
                "url": "https://blog.example.test/2026/the-garden-party-guide",
                "content": "Plan the garden before the frost ends.",
            }
        ],
    }
    result, failure, raw_call = await _adjudicate(
        _enriched(), extra_hosts=("garden",), loop_messages=_tool_messages(search)
    )
    assert failure == {}
    assert result is not None
    sent = raw_call.await_args.args[0]
    # The standalone word is still labelled. The URL path keeps its words.
    assert "Plan the garden" not in sent
    assert "the-garden-party-guide" in sent


# ── Negative controls: what the guard must still catch ──────────────────────


async def test_a_host_shaped_unc_name_still_refuses_and_names_its_source() -> None:
    """A real-looking UNC host learned from the payload, then seen where no
    replacer reaches: the guard still refuses, and says where it learned it."""
    enriched = _enriched(
        payload_printable="SMB2 tree connect \\\\filesrv9\\finance$ ok",
        message="backup to filesrv9-archive finished",
    )
    result, failure, raw_call = await _adjudicate(enriched)
    assert result is None
    raw_call.assert_not_awaited()
    assert failure["reason"] == "residue_refusal"
    assert failure["error_class"] == "refused"
    assert failure["message"] == (
        "residue: residual learned value, learned by the UNC rule in "
        "alert_summary.alert.payload_printable"
    )
    # The value itself is never in the reason.
    assert "filesrv9" not in failure["message"]


def test_a_short_name_from_a_structured_field_stays_learned() -> None:
    """The shape rule is for free text. ``host.name: db`` is a field role."""
    m = Mapping()
    m.label_for("db", "HOST")
    assert "db" in m.learned_values()
    assert m.in_place_only == set()


def test_a_text_name_seen_later_in_a_field_joins_the_learned_set() -> None:
    m = Mapping()
    m.label_for("tp", "HOST", text_rule="UNC")
    assert "tp" in m.in_place_only
    assert "tp" not in m.learned_values()
    m.label_for("tp", "HOST")
    assert "tp" in m.learned_values()


def test_the_shape_rule() -> None:
    for bad in ("TP", "zq", "aB..c..1", "a/b/c", "x\\y\\z", "garden", "Water", "..", "a.b"):
        assert plausible_learned_host(bad) is False, bad
    for good in ("filesrv9", "DESKTOP-AB12", "dc01.corp.example.test", "FS1"):
        assert plausible_learned_host(good) is True, good


def test_the_analyst_egress_guard_keeps_a_short_text_name_out_of_its_learned_set() -> None:
    """The analyst path shares the Mapping: a 2-letter UNC host is labelled in
    place and the same token in a stats key does not fail the composed prompt."""
    guard = EgressGuard(extra_hosts=(), extra_suffixes=SUFFIXES)
    sanitized = guard.sanitize_text("dump .:\\\\TP\\xY end")
    assert "\\\\TP\\" not in sanitized
    composed = json.dumps({"payload": sanitized, "stats": {"tp": 0, "fp": 3}})
    assert guard.residue(composed) == []
