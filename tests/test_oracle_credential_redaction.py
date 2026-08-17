"""Tests for credential-context username redaction in the Oracle privacy gate.

Closes the security-review finding: a bare username appearing ONLY in a
free-text field in an explicit credential context (``user=jdoe``,
``username: svc-bak``, ``DOMAIN\\jdoe``) was learned by no field role and matched
no shape rule, so it egressed verbatim to the cloud Oracle.

Covers:
- ``redact.sanitize_case`` tokenises credential-context usernames + NetBIOS
  ``DOMAIN\\user`` logon names, round-tripping via ``desanitize``.
- Universal built-in accounts (root/SYSTEM/Administrator) and non-username
  tokens (booleans, numbers) are left untouched — Oracle utility preserved.
- Public emails and public FQDNs are NOT mangled (no over-redaction).
- The independent ``unsafe_residue`` net flags an unredacted credential
  username and clears the redacted (labelled) form.
- ``_warn_if_privacy_gate_unconfigured`` fires once when the Oracle is enabled
  with the privacy gate left at defaults.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import pytest
from pydantic import SecretStr
from soc_ai.config import Settings
from soc_ai.oracle import client as oracle_client
from soc_ai.oracle.redact import Mapping, sanitize_case
from soc_ai.oracle.sanitize import desanitize, unsafe_residue


def _redact(case: dict[str, Any]) -> tuple[dict[str, Any], Mapping]:
    mapping = Mapping()
    out = sanitize_case(case, mapping)
    return out, mapping


def _residue(sanitized: dict[str, Any], mapping: Mapping) -> list[str]:
    """Run the independent residue sweep exactly as the client does.

    The client scans ``json.dumps`` output, so this passes ``wire_escaped=True``
    to mirror it faithfully (a lone single backslash in the blob is a JSON escape,
    not a NetBIOS separator).
    """
    payload = json.dumps(sanitized)
    return unsafe_residue(payload, known_values=tuple(mapping.reverse.values()), wire_escaped=True)


# ---------------------------------------------------------------------------
# 1. key=value credential forms are redacted
# ---------------------------------------------------------------------------


class TestCredentialKeyValue:
    def test_user_equals_is_redacted(self) -> None:
        out, mapping = _redact({"message": "Failed logon for user=jdoe from gateway"})
        msg = out["message"]
        assert "jdoe" not in msg
        assert "USER_01" in msg
        # round-trips
        assert "jdoe" in desanitize(msg, mapping)
        # and the outbound payload is clean
        assert _residue(out, mapping) == []

    def test_username_colon_space_is_redacted(self) -> None:
        out, _ = _redact({"message": "username: svc-backup logged in"})
        assert "svc-backup" not in out["message"]
        assert "USER_01" in out["message"]

    def test_account_and_acct_and_samaccountname(self) -> None:
        for line in ("account=alice", "acct=alice", "sAMAccountName=alice", "user_name=alice"):
            out, _ = _redact({"message": f"event {line} here"})
            assert "alice" not in out["message"], line
            assert "USER_01" in out["message"], line

    def test_quoted_value_is_redacted_quotes_preserved(self) -> None:
        out, _ = _redact({"message": 'logon user="jdoe" ok'})
        # The username is gone but the surrounding quotes remain.
        assert "jdoe" not in out["message"]
        assert '"USER_01"' in out["message"]

    def test_dotted_username_is_redacted_whole(self) -> None:
        out, _ = _redact({"message": "user=a.smith authenticated"})
        assert "a.smith" not in out["message"]
        assert "USER_01" in out["message"]


# ---------------------------------------------------------------------------
# 2. NetBIOS DOMAIN\user logon names
# ---------------------------------------------------------------------------


class TestNetbiosLogon:
    def test_domain_and_user_both_redacted(self) -> None:
        out, mapping = _redact({"message": r"Interactive logon ACMECORP\jdoe succeeded"})
        msg = out["message"]
        assert "ACMECORP" not in msg
        assert "jdoe" not in msg
        # HOST and USER use independent per-category counters → both _01.
        assert "HOST_01" in msg and "USER_01" in msg
        assert _residue(out, mapping) == []

    def test_builtin_authority_domain_and_system_user_pass(self) -> None:
        # NT AUTHORITY\SYSTEM is universal — neither part is internal-identifying.
        out, _ = _redact({"message": r"NT AUTHORITY\SYSTEM ran the service"})
        assert "SYSTEM" in out["message"]
        # AUTHORITY is in the NT-domain stopset, so it is not tokenised.
        assert "AUTHORITY" in out["message"]

    def test_windows_path_not_treated_as_netbios(self) -> None:
        # A real filesystem path must not have "Users" mis-read as a domain.
        out, _ = _redact({"message": r"dropped to C:\Users\Public\Downloads\x.exe"})
        assert "HOST_01" not in out["message"]
        assert r"C:\Users\Public" in out["message"]


# ---------------------------------------------------------------------------
# 3. Built-ins / non-usernames are preserved (Oracle utility)
# ---------------------------------------------------------------------------


class TestPreservedTokens:
    def test_builtin_accounts_pass(self) -> None:
        for builtin in ("root", "SYSTEM", "Administrator", "guest", "www-data"):
            out, _ = _redact({"message": f"user={builtin} did a thing"})
            assert builtin in out["message"], builtin
            assert "USER_" not in out["message"], builtin

    def test_boolean_status_values_pass(self) -> None:
        for val in ("disabled", "true", "failed", "unknown"):
            out, _ = _redact({"message": f"account={val}"})
            assert val in out["message"], val
            assert "USER_" not in out["message"], val

    def test_numeric_value_passes(self) -> None:
        out, _ = _redact({"message": "account=1000 numeric"})
        assert "1000" in out["message"]
        assert "USER_" not in out["message"]

    def test_public_email_not_mangled(self) -> None:
        # alice@gmail.com is a public email — the credential pass must not clip
        # the local-part, and the public email must pass through verbatim.
        out, _ = _redact({"message": "phish targeted user=alice@gmail.com today"})
        assert "alice@gmail.com" in out["message"]
        assert "USER_" not in out["message"]

    def test_public_fqdn_passes(self) -> None:
        # Regression: the Oracle must still see public threat infrastructure.
        out, _ = _redact({"message": "beacon to login.evil-c2.example.com observed"})
        assert "login.evil-c2.example.com" in out["message"]

    def test_superuser_not_matched(self) -> None:
        # The "user" inside "superuser" must not anchor a credential match.
        out, _ = _redact({"message": "ran as superuser context"})
        assert "superuser" in out["message"]
        assert "USER_" not in out["message"]


# ---------------------------------------------------------------------------
# 4. Idempotency / already-labelled
# ---------------------------------------------------------------------------


class TestIdempotency:
    def test_already_labelled_value_untouched(self) -> None:
        out, _ = _redact({"message": "user=USER_01 from a prior pass"})
        assert out["message"] == "user=USER_01 from a prior pass"

    def test_double_sanitize_stable(self) -> None:
        case = {"message": r"user=jdoe and CORP\bsmith"}
        out1, m1 = _redact(case)
        # Re-running over the already-sanitized output must not re-tokenise.
        out2 = sanitize_case(out1, m1)
        assert out1 == out2


# ---------------------------------------------------------------------------
# 5. Independent residue net
# ---------------------------------------------------------------------------


class TestResidueCredentials:
    def test_unredacted_username_is_flagged(self) -> None:
        leaks = unsafe_residue('{"message": "user=jdoe leaked"}')
        assert any("credential username" in m for m in leaks)

    def test_unredacted_netbios_is_flagged(self) -> None:
        # json.dumps would escape the backslash; emulate that.
        leaks = unsafe_residue('{"message": "ACMECORP\\\\jdoe leaked"}')
        assert any("credential username" in m for m in leaks)

    def test_labelled_form_is_clean(self) -> None:
        leaks = unsafe_residue('{"message": "user=USER_01 ok"}')
        assert leaks == []

    def test_builtin_not_flagged(self) -> None:
        leaks = unsafe_residue('{"message": "user=SYSTEM ok"}')
        assert [m for m in leaks if "credential username" in m] == []

    def test_public_email_not_flagged(self) -> None:
        leaks = unsafe_residue('{"message": "user=alice@gmail.com"}')
        assert [m for m in leaks if "credential username" in m] == []

    def test_allowlisted_username_not_flagged(self) -> None:
        leaks = unsafe_residue('{"message": "user=jdoe"}', allowlist=["jdoe"])
        assert [m for m in leaks if "credential username" in m] == []


# ---------------------------------------------------------------------------
# 6. Operator-awareness warning
# ---------------------------------------------------------------------------


def _settings(**kwargs: Any) -> Settings:
    base: dict[str, Any] = {
        "so_host": "https://so.example.com",
        "so_username": "analyst",
        "so_password": SecretStr("password123"),
        "es_hosts": ["https://so.example.com:9200"],
        "litellm_base_url": "http://localhost:4000",
        "oracle_enabled": True,
    }
    base.update(kwargs)
    return Settings(**base)


class TestUnconfiguredWarning:
    def _reset(self) -> None:
        oracle_client._UNCONFIGURED_WARNED[0] = False

    def test_warns_when_enabled_and_default(self, caplog: Any) -> None:
        self._reset()
        with caplog.at_level(logging.WARNING):
            oracle_client._warn_if_privacy_gate_unconfigured(_settings())
        assert any("no organisation-specific internal names" in r.message for r in caplog.records)

    def test_warns_only_once(self, caplog: Any) -> None:
        self._reset()
        with caplog.at_level(logging.WARNING):
            oracle_client._warn_if_privacy_gate_unconfigured(_settings())
            oracle_client._warn_if_privacy_gate_unconfigured(_settings())
        warnings = [r for r in caplog.records if "internal names" in r.message]
        assert len(warnings) == 1

    def test_silent_when_extra_hosts_set(self, caplog: Any) -> None:
        self._reset()
        with caplog.at_level(logging.WARNING):
            oracle_client._warn_if_privacy_gate_unconfigured(
                _settings(oracle_extra_hosts=["WIN11-01"])
            )
        assert not any("internal names" in r.message for r in caplog.records)

    def test_silent_when_custom_suffix_set(self, caplog: Any) -> None:
        self._reset()
        with caplog.at_level(logging.WARNING):
            oracle_client._warn_if_privacy_gate_unconfigured(
                _settings(oracle_internal_suffixes=".lan,.local,.internal,.corp,ad.acme.com")
            )
        assert not any("internal names" in r.message for r in caplog.records)

    def test_silent_when_oracle_disabled(self, caplog: Any) -> None:
        self._reset()
        with caplog.at_level(logging.WARNING):
            oracle_client._warn_if_privacy_gate_unconfigured(_settings(oracle_enabled=False))
        assert not any("internal names" in r.message for r in caplog.records)

    def test_silent_when_effective_hosts_supplied_despite_empty_settings(self, caplog: Any) -> None:
        """A DB-only deployment (empty .env, internal names via the DB) supplies a
        non-empty effective host set → no spurious warning even though the raw
        settings are at their defaults."""
        self._reset()
        with caplog.at_level(logging.WARNING):
            oracle_client._warn_if_privacy_gate_unconfigured(
                _settings(),  # raw settings: no extra hosts, default suffixes
                effective_hosts=("WIN11-01",),
                effective_suffixes=(".lan", ".local", ".internal", ".corp"),
            )
        assert not any("internal names" in r.message for r in caplog.records)

    def test_silent_when_effective_suffix_supplied_despite_empty_settings(
        self, caplog: Any
    ) -> None:
        """Same, but the internal name was discovered as a custom suffix."""
        self._reset()
        with caplog.at_level(logging.WARNING):
            oracle_client._warn_if_privacy_gate_unconfigured(
                _settings(),
                effective_hosts=(),
                effective_suffixes=(".lan", ".local", ".internal", ".corp", ".ad.acme.com"),
            )
        assert not any("internal names" in r.message for r in caplog.records)

    def test_still_warns_when_effective_set_also_empty(self, caplog: Any) -> None:
        """An explicit empty effective set (no DB config either) → the warning
        still fires; threading the resolved set does not silence a genuinely
        unconfigured gate."""
        self._reset()
        with caplog.at_level(logging.WARNING):
            oracle_client._warn_if_privacy_gate_unconfigured(
                _settings(),
                effective_hosts=(),
                effective_suffixes=(".lan", ".local", ".internal", ".corp"),
            )
        assert any("no organisation-specific internal names" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# 7. Code-review follow-ups
# ---------------------------------------------------------------------------


class TestResidueKeyParity:
    """Finding 1: the residue net must cover the full redacter key set so it is a
    genuine fail-closed backstop (catches a redacter miss on account/acct/usr)."""

    def test_residue_flags_account_acct_usr(self) -> None:
        for key in ("account", "acct", "usr"):
            leaks = unsafe_residue(f'{{"m": "{key}=jdoe"}}')
            assert any("credential username" in m for m in leaks), key

    def test_residue_still_silent_on_redacted_account(self) -> None:
        # Normal flow: redacter tokenised it first → residue sees a label → silent.
        out, mapping = _redact({"message": "account=jdoe here"})
        assert _residue(out, mapping) == []


class TestNoGlobalPropagation:
    """Finding 2: a free-text credential value must NOT be globally propagated —
    propagating it could corrupt a public IOC that follows ``user=``."""

    def test_credential_value_not_propagated_to_other_field(self) -> None:
        # 'mimikatz' as a username must not silently rewrite the IOC elsewhere.
        out, mapping = _redact({"message": "user=mimikatz", "ioc": "process mimikatz.exe on disk"})
        assert "USER_01" in out["message"]  # redacted in its credential context
        assert "mimikatz" in out["ioc"]  # public IOC NOT corrupted
        # ...but the residue gate fails closed on the bare re-occurrence (no leak).
        assert any("learned value" in m or "credential" in m for m in _residue(out, mapping))

    def test_two_credential_contexts_both_redacted_in_place(self) -> None:
        out, mapping = _redact({"message": "user=jdoe then account=jdoe"})
        assert "jdoe" not in out["message"]
        assert out["message"].count("USER_01") == 2  # same value → same label
        assert _residue(out, mapping) == []


class TestNetbiosMinDomainLength:
    """Finding 3: a single-character token (drive letter) must not be read as a
    NetBIOS domain and over-redacted/propagated."""

    def test_single_char_domain_not_redacted(self) -> None:
        out, _ = _redact({"message": r"wrote C\smith to disk"})
        assert "HOST_" not in out["message"]
        assert r"C\smith" in out["message"]

    def test_two_char_domain_is_redacted(self) -> None:
        out, _ = _redact({"message": r"logon XY\jdoe ok"})
        assert "HOST_01" in out["message"] and "USER_01" in out["message"]
        assert "jdoe" not in out["message"]


class TestRedosBounds:
    """Pre-existing ReDoS in the suffix-FQDN + email redaction regexes: a long
    hyphenated run in attacker-controlled free text must not hang the gate."""

    def test_hyphen_run_completes_fast(self) -> None:
        """Asserts SCALING, not wall-clock.

        A stopwatch bound measures the machine, not the regex. This test was
        first written with an absolute deadline, and chased it twice: it timed
        regex COMPILATION and so failed cold while passing warm (fixed by
        warming outside the timed section), then failed at 2.34s against a 2.0s
        bound on 2026-08-07 purely from CPU contention. Doubling the input is
        load-invariant — catastrophic backtracking is superlinear (quadratic
        gives 4x, exponential far worse) while a bounded quantifier is linear,
        and both measurements slow down together under load.
        """
        import time

        def build(n: int) -> dict[str, str]:
            return {
                "message": "user=" + ("a-" * n),
                "payload_printable": ("z-" * n) + " end",
                "rule_name": ("w." * n) + "x",
            }

        def elapsed(case: dict[str, str]) -> float:
            start = time.perf_counter()
            mapping = Mapping()
            out = sanitize_case(case, mapping)
            unsafe_residue(json.dumps(out), known_values=tuple(mapping.reverse.values()))
            return time.perf_counter() - start

        elapsed(build(50))  # warm every pattern's compile before anything is timed
        single = elapsed(build(10000))
        double = elapsed(build(20000))
        scaling = double / max(single, 1e-6)
        assert scaling < 3.0, f"redaction scaled {scaling:.2f}x on 2x input (linear is 2.0)"

    def test_real_suffix_fqdn_still_redacted(self) -> None:
        # The bound must not break matching of a normal internal FQDN.
        out, _ = _redact({"message": "beacon from dc01.ad.lan internal"})
        assert "dc01.ad.lan" not in out["message"]
        assert "HOST_01" in out["message"]

    def test_real_internal_email_still_redacted(self) -> None:
        out, _ = _redact({"message": "from admin@corp.lan today"})
        assert "admin@corp.lan" not in out["message"]
        assert "EMAIL_01" in out["message"]


# ---------------------------------------------------------------------------
# 8. Windows credential renderings (finding windows-credential-silent-egress)
# ---------------------------------------------------------------------------
#
# Six shapes leaked the username VERBATIM through the real pipeline
# (sanitize_case → json.dumps → unsafe_residue == []).  Each is a distinct
# rendering of the SAME internal username; all must be redacted by the replacer
# AND independently flaggable by the residue net (detector ⊆ replacer).


class TestWindowsCredentialShapes:
    def test_account_name_message_form(self) -> None:
        # 4624/4625 message rendering: "Account Name:  jdoe" — Account+space+Name
        # matches no key alternation.
        out, mapping = _redact({"message": "Account Name:  jdoe"})
        assert "jdoe" not in out["message"]
        assert "USER_01" in out["message"]
        assert _residue(out, mapping) == []

    def test_account_domain_message_form(self) -> None:
        # "Account Domain:  ACMECORP" — the NetBIOS domain is a HOST identifier.
        out, mapping = _redact({"message": "Account Domain:  ACMECORP here"})
        assert "ACMECORP" not in out["message"]
        assert "HOST_01" in out["message"]
        assert _residue(out, mapping) == []

    def test_target_user_name_kv(self) -> None:
        # "TargetUserName=jdoe" — the (?<![\w.]) lookbehind rejected mid-word
        # UserName, so no key matched.
        out, mapping = _redact({"message": "Kerberos TargetUserName=jdoe from host"})
        assert "jdoe" not in out["message"]
        assert "USER_01" in out["message"]
        assert _residue(out, mapping) == []

    def test_target_user_name_json_quoted(self) -> None:
        # '"TargetUserName": "jdoe"' — the quote between key and colon defeated
        # both KV regexes.
        out, mapping = _redact({"message": '"TargetUserName": "jdoe"'})
        assert "jdoe" not in out["message"]
        assert "USER_01" in out["message"]
        assert _residue(out, mapping) == []

    @pytest.mark.parametrize(
        "leaf", ["TargetUserName", "SubjectUserName", "SamAccountName", "AccountName"]
    )
    def test_structured_winlog_leaf_key(self, leaf: str) -> None:
        # {"winlog":{"event_data":{"<leaf>": ...}}} — leaf key not in _USER_FIELDS.
        out, mapping = _redact({"winlog": {"event_data": {leaf: "jdoe"}}})
        assert "jdoe" not in json.dumps(out)
        assert "USER_01" in json.dumps(out)
        assert _residue(out, mapping) == []

    def test_oql_user_name_dotted(self) -> None:
        # "user.name:jdoe" — the agent's own OQL quoted back; the dot defeated the
        # alternation.
        out, mapping = _redact({"summary": "pivot on user.name:jdoe next"})
        assert "jdoe" not in out["summary"]
        assert "USER_01" in out["summary"]
        assert _residue(out, mapping) == []


class TestNetbiosBackslashMultiplicity:
    def test_single_backslash_redacts(self) -> None:
        # Control case: one literal backslash already redacted.
        out, mapping = _redact({"message": r"Interactive logon ACMECORP\jdoe ok"})
        assert "jdoe" not in out["message"]
        assert "ACMECORP" not in out["message"]
        assert "HOST_01" in out["message"] and "USER_01" in out["message"]
        assert _residue(out, mapping) == []

    def test_double_backslash_redacts(self) -> None:
        # The gap: a winlog / nested-JSON message field carrying TWO literal
        # backslashes.  json.dumps doubles it to four on the wire.
        out, mapping = _redact({"message": "Interactive logon ACMECORP\\\\jdoe ok"})
        assert "jdoe" not in out["message"]
        assert "ACMECORP" not in out["message"]
        assert _residue(out, mapping) == []


class TestResidueWindowsShapes:
    """The independent residue net flags each shape when the replacer MISSES it —
    the fail-closed backstop is at least as broad as the replacer."""

    def test_residue_flags_target_user_name_kv(self) -> None:
        leaks = unsafe_residue('{"m": "TargetUserName=jdoe"}')
        assert any("credential" in m for m in leaks)

    def test_residue_flags_json_quoted_key(self) -> None:
        # The wire form: json.dumps escaped the inner quotes.
        wire = json.dumps({"m": '"TargetUserName": "jdoe"'})
        leaks = unsafe_residue(wire)
        assert any("credential" in m for m in leaks)

    def test_residue_flags_account_name(self) -> None:
        leaks = unsafe_residue('{"m": "Account Name:  jdoe"}')
        assert any("credential" in m for m in leaks)

    def test_residue_flags_four_backslash_netbios(self) -> None:
        # Two backslashes in the dict value → four on the json.dumps'd wire.
        wire = json.dumps({"m": "ACMECORP\\\\jdoe"})
        leaks = unsafe_residue(wire)
        assert any("credential" in m for m in leaks)

    def test_residue_silent_on_labelled_winlog(self) -> None:
        out, mapping = _redact({"winlog": {"event_data": {"TargetUserName": "jdoe"}}})
        assert _residue(out, mapping) == []


# Every distinct Windows credential rendering that leaked, each carrying the same
# username ``jdoe`` (and one carrying the NetBIOS domain ``ACMECORP``).
_WIRE_PROPERTY_CASES: list[dict[str, Any]] = [
    {"message": "Account Name:  jdoe"},
    {"message": "TargetUserName=jdoe"},
    {"message": '"TargetUserName": "jdoe"'},
    {"winlog": {"event_data": {"TargetUserName": "jdoe"}}},
    {"winlog": {"event_data": {"SubjectUserName": "jdoe"}}},
    {"winlog": {"event_data": {"SamAccountName": "jdoe"}}},
    {"summary": "pivot on user.name:jdoe"},
    {"message": r"logon ACMECORP\jdoe"},  # one backslash
    {"message": "logon ACMECORP\\\\jdoe"},  # two backslashes
]


class TestPipelineWireProperty:
    """Pipeline property (detector ⊆ replacer on every egress path): across
    backslash-multiplicity {1,2} and KV / NetBIOS / JSON variants, the username
    never appears on the json.dumps'd wire payload, and the independent residue
    net is clean."""

    @pytest.mark.parametrize("case", _WIRE_PROPERTY_CASES)
    def test_username_never_on_wire(self, case: dict[str, Any]) -> None:
        mapping = Mapping()
        out = sanitize_case(case, mapping)
        wire = json.dumps(out)
        assert "jdoe" not in wire, wire
        assert unsafe_residue(wire, known_values=tuple(mapping.reverse.values())) == []


class TestWindowsShapesNoOverRedaction:
    """The widening must NOT over-redact public IOCs — the tension the whole
    subsystem is built around."""

    def test_winlog_builtin_user_preserved(self) -> None:
        # A universal built-in in a winlog leaf key is NOT internal-identifying.
        out, _ = _redact({"winlog": {"event_data": {"TargetUserName": "SYSTEM"}}})
        wire = json.dumps(out)
        assert "SYSTEM" in wire
        assert "USER_" not in wire

    def test_winlog_null_dash_preserved(self) -> None:
        # Windows renders an absent account as "-"; never tokenise it.
        out, _ = _redact({"winlog": {"event_data": {"SubjectUserName": "-"}}})
        assert json.dumps(out).count("USER_") == 0

    def test_public_fqdn_preserved_alongside_account_name(self) -> None:
        out, _ = _redact(
            {"message": "Account Name:  jdoe", "ioc": "c2 at login.evil-c2.example.com"}
        )
        assert "login.evil-c2.example.com" in out["ioc"]

    def test_malware_family_username_not_globally_propagated(self) -> None:
        # A free-text credential value must not rewrite a public IOC elsewhere.
        out, _ = _redact({"message": "TargetUserName=mimikatz", "ioc": "process mimikatz.exe"})
        assert "USER_01" in out["message"]  # redacted in its credential context
        assert "mimikatz.exe" in out["ioc"]  # public IOC NOT corrupted


# ---------------------------------------------------------------------------
# 9. Widening remediation — the NT-authority and path over-redaction regressions
# ---------------------------------------------------------------------------


class TestAccountDomainNtAuthority:
    """``Account Domain:  NT AUTHORITY`` must pass through untouched — the value
    capture stops at the first space (``NT``), which is not an identifying
    domain."""

    @pytest.mark.parametrize("domain", ["NT AUTHORITY", "NT SERVICE", "BUILTIN"])
    def test_universal_domains_preserved(self, domain: str) -> None:
        out, mapping = _redact({"message": f"Account Domain:  {domain} here"})
        assert out["message"] == f"Account Domain:  {domain} here"
        assert "HOST_" not in out["message"]
        assert _residue(out, mapping) == []

    def test_real_domain_still_redacted(self) -> None:
        # A genuine NetBIOS domain in the same field IS still tokenised.
        out, mapping = _redact({"message": "Account Domain:  ACMECORP here"})
        assert "ACMECORP" not in out["message"]
        assert "HOST_01" in out["message"]
        assert _residue(out, mapping) == []


class TestResidueAccountDomain:
    """Residue mirror: the NT-authority stopset applies in the domain context."""

    @pytest.mark.parametrize("domain", ["NT AUTHORITY", "NT SERVICE", "BUILTIN"])
    def test_universal_domains_not_flagged(self, domain: str) -> None:
        leaks = unsafe_residue(f'{{"m": "Account Domain:  {domain}"}}')
        assert [m for m in leaks if "credential" in m] == []

    def test_real_domain_is_flagged(self) -> None:
        leaks = unsafe_residue('{"m": "Account Domain:  ACMECORP"}')
        assert any("credential domain" in m for m in leaks)


class TestNetbiosPathNotCredential:
    """The widened NetBIOS separator must NOT fire on a registry/path fragment —
    ``HKLM\\Software`` is a path, not a down-level logon name."""

    @pytest.mark.parametrize(
        "value",
        [
            r"Reg key HKLM\Software modified",  # one backslash
            "Reg key HKLM\\\\Software modified",  # two backslashes (winlog/JSON form)
            r"HKCU\Environment set",
            r"HKEY_LOCAL_MACHINE\System touched",
        ],
    )
    def test_registry_paths_preserved(self, value: str) -> None:
        out, mapping = _redact({"message": value})
        assert out["message"] == value
        assert "HOST_" not in out["message"] and "USER_" not in out["message"]
        assert _residue(out, mapping) == []

    def test_genuine_logon_still_redacted_single_and_double(self) -> None:
        for raw in (r"logon CORP\jdoe ok", "logon CORP\\\\jdoe ok"):
            out, mapping = _redact({"message": raw})
            assert "jdoe" not in out["message"]
            assert "CORP" not in out["message"]
            assert "HOST_01" in out["message"] and "USER_01" in out["message"]
            assert _residue(out, mapping) == []


class TestResidueNetbiosPathNotCredential:
    """Residue mirror: a doubly-escaped path fragment on the wire (four
    backslashes) must NOT trip the fail-closed gate, while a genuine four-
    backslash logon name still does."""

    def test_wire_registry_path_not_flagged(self) -> None:
        wire = json.dumps({"m": "Reg key HKLM\\\\Software modified"})  # 4 backslashes on the wire
        assert [m for m in unsafe_residue(wire) if "credential" in m] == []

    def test_wire_genuine_logon_is_flagged(self) -> None:
        wire = json.dumps({"m": "CORP\\\\jdoe"})  # 4 backslashes on the wire
        assert any("credential" in m for m in unsafe_residue(wire))


# ---------------------------------------------------------------------------
# 10. WIRE mode: a JSON-escaped newline/tab must not read as a NetBIOS separator
#     (finding residue-gate-json-newline-fp)
# ---------------------------------------------------------------------------
#
# On the WIRE (a ``json.dumps`` blob, ``wire_escaped=True``) a real newline is the
# TWO characters ``\`` + ``n`` (a SINGLE literal backslash).  The NetBIOS
# ``DOMAIN\user`` net treated a single backslash as a separator, so an ordinary
# multi-line transcript (``…a CDN\nVerdict…``) parsed as ``CDN\nVerdict`` and
# refused every real transcript.  In WIRE mode a GENUINE down-level logon always
# carries ``\\`` (a raw ``DOMAIN\jdoe`` → two wire backslashes; a doubled winlog
# ``DOMAIN\\jdoe`` → four), so the ``\\{2,4}`` separator catches it while ignoring
# the lone escape backslash.  (The RAW single-backslash behavior is covered by
# ``TestResidueRawSingleBackslash`` below and the demo publish-gate test.)


class TestResidueJsonNewlineFalsePositive:
    def test_multiline_transcript_no_residue(self) -> None:
        # The exact reported FP: a benign multi-line loop transcript, scanned as
        # the client scans it (WIRE mode).
        case = {
            "loop_evidence": (
                "the domain resolves to a CDN\n"
                "Verdict basis: benign traffic\t"
                "no credential material present\r\n"
                "second line begins"
            )
        }
        mapping = Mapping()
        out = sanitize_case(case, mapping)
        wire = json.dumps(out)
        leaks = unsafe_residue(
            wire, known_values=tuple(mapping.reverse.values()), wire_escaped=True
        )
        assert leaks == [], leaks

    def test_json_escape_letters_not_separators(self) -> None:
        # Each JSON escape (\n \t \r \") is a single wire backslash; none may be
        # read as a NetBIOS ``DOMAIN\user`` separator in WIRE mode.
        for esc in ("word\nother", "word\tother", "word\rother", 'word"other'):
            leaks = unsafe_residue(json.dumps({"m": esc}), wire_escaped=True)
            assert [m for m in leaks if "credential" in m] == [], (esc, leaks)

    def test_genuine_netbios_still_flags_two_and_four_wire_backslashes(self) -> None:
        # Two wire backslashes = one real backslash (raw ``DOMAIN\jdoe``).
        two = json.dumps({"m": "ACMECORP\\jdoe"})
        assert any("credential" in m for m in unsafe_residue(two, wire_escaped=True)), two
        # Four wire backslashes = doubled winlog form (``DOMAIN\\jdoe``).
        four = json.dumps({"m": "ACMECORP\\\\jdoe"})
        assert any("credential" in m for m in unsafe_residue(four, wire_escaped=True)), four


class TestResidueRawSingleBackslash:
    """RAW mode (the default) — the demo publish leak gate and the analyst egress
    guard scan un-serialized values, where a genuine down-level logon carries a
    SINGLE backslash.  It must be caught even when the username STARTS with a JSON
    escape letter (n/t/r/b/f/u) — the case an escape-letter lookahead would have
    silently dropped."""

    @pytest.mark.parametrize("user", ["jdoe", "nancy", "frank", "bob", "tom", "rick", "ursula"])
    def test_single_backslash_logon_flagged_raw(self, user: str) -> None:
        raw = f"logon as CORP\\{user} failed"  # one literal backslash before the name
        leaks = unsafe_residue(raw)  # default wire_escaped=False
        assert any("credential" in m for m in leaks), (user, leaks)

    def test_hive_prefix_still_skipped_raw(self) -> None:
        # The batch-1 hive skip must hold in RAW mode: HKLM\Software is a path.
        leaks = unsafe_residue(r"Reg key HKLM\Software modified")
        assert [m for m in leaks if "credential" in m] == [], leaks


# ---------------------------------------------------------------------------
# 11. Pass-2-learned values propagate before serialization; short no-propagate
#     values are threaded out so they don't force a refusal
#     (finding oracle-refuse-by-design)
# ---------------------------------------------------------------------------


class TestPass2LearnedPropagation:
    """Class 1: a credential value learned DURING Pass 2 (in-place-only) that also
    appears bare in another field must be propagated there before serialization,
    so the payload egresses FULLY LABELLED instead of tripping the residue gate
    by construction."""

    def test_two_occurrence_credential_fully_labelled(self) -> None:
        out, mapping = _redact(
            {"message": "logon user=jdoe ok", "summary": "jdoe touched the share"}
        )
        assert "jdoe" not in out["summary"]
        assert "USER_01" in out["summary"]
        assert "USER_01" in out["message"]
        # Egresses (residue clean) rather than refusing by construction.
        assert _residue(out, mapping) == []

    def test_learned_netbios_domain_and_user_propagated(self) -> None:
        # A NetBIOS domain (ACMECORP) and username (jdoe) learned only in the
        # credential context of ``message`` re-occur bare in ``summary``.
        out, mapping = _redact(
            {
                "message": r"Interactive logon ACMECORP\jdoe",
                "summary": "jdoe on ACMECORP touched the share",
            }
        )
        assert "jdoe" not in out["summary"]
        assert "ACMECORP" not in out["summary"]
        assert _residue(out, mapping) == []

    def test_resweep_preserves_public_ioc_substring(self) -> None:
        # The propagation must never splice a learned value into a compound token
        # (filename / FQDN); mimikatz.exe stays intact and fails closed instead.
        out, _ = _redact(
            {"message": "TargetUserName=mimikatz", "ioc": "process mimikatz.exe on disk"}
        )
        assert "USER_01" in out["message"]
        assert "mimikatz.exe" in out["ioc"]


class TestNoPropagateThreadedOut:
    """Class 2: short (<=3 char) DOMAIN_LIKE values are intentionally NOT
    globally propagated (they would corrupt public FQDNs), but the ``no_propagate``
    set was local to sanitize_case and never reached the client, so the residue
    gate flagged the bare public occurrence and refused. Thread it out and exclude
    it from known_values."""

    def test_sanitize_case_reports_no_propagate_values(self) -> None:
        mapping = Mapping()
        collected: set[str] = set()
        sanitize_case(
            {"alert": {"zeek_dns_query": "dc"}, "note": "lookup dc.example.com"},
            mapping,
            no_propagate_out=collected,
        )
        assert "dc" in collected

    def test_short_label_excluded_from_known_values_is_clean(self) -> None:
        # Emulate the client: exclude no_propagate values from known_values.
        mapping = Mapping()
        collected: set[str] = set()
        out = sanitize_case(
            {"alert": {"zeek_dns_query": "dc"}, "note": "lookup dc.example.com"},
            mapping,
            no_propagate_out=collected,
        )
        known = tuple(v for v in mapping.reverse.values() if v not in collected)
        assert unsafe_residue(json.dumps(out), known_values=known) == []
        # The public FQDN survives verbatim.
        assert "dc.example.com" in out["note"]


# ---------------------------------------------------------------------------
# 12. Redacter and residue net share credential DATA, keep independent engines
#     (finding oracle-cred-twin-nets)
# ---------------------------------------------------------------------------


class TestCredNetDataParity:
    """The two nets keep independent regex ENGINES but must share the credential
    DATA — a stopword or key added to one net but not the other silently diverges
    and causes a permanent Oracle refusal. Assert both modules source the SAME
    objects, so they cannot drift."""

    def test_value_stopset_is_the_shared_object(self) -> None:
        from soc_ai.oracle import _cred_data, redact, sanitize

        assert redact._CRED_VALUE_STOPSET is _cred_data.CRED_VALUE_STOPSET
        assert sanitize._RESIDUE_CRED_STOPSET is _cred_data.CRED_VALUE_STOPSET

    def test_credential_keys_are_the_shared_object(self) -> None:
        from soc_ai.oracle import _cred_data, redact

        assert redact._CRED_KEYS is _cred_data.CRED_KEYS


# A corpus of credential renderings — one per shape both nets recognise.
_CRED_PARITY_CORPUS: list[dict[str, Any]] = [
    {"message": "user=jdoe logged on"},
    {"message": "username: svc-backup ok"},
    {"message": "account=alice here"},
    {"message": "acct=alice here"},
    {"message": "usr=bob here"},
    {"message": "sAMAccountName=alice here"},
    {"message": "user_name=alice here"},
    {"message": 'logon user="jdoe" ok'},
    {"message": "user=a.smith authenticated"},
    {"message": r"Interactive logon ACMECORP\jdoe succeeded"},
    {"message": "Account Name:  jdoe"},
    {"message": "Account Domain:  ACMECORP here"},
    {"message": "Kerberos TargetUserName=jdoe from host"},
    {"message": '"TargetUserName": "jdoe"'},
    {"winlog": {"event_data": {"TargetUserName": "jdoe"}}},
    {"winlog": {"event_data": {"SubjectUserName": "svc-bak"}}},
    {"summary": "pivot on user.name:jdoe next"},
]


class TestCredNetBehaviouralParity:
    """Parity invariant: the independent residue net must NEVER fire on the
    redacter's own output across a corpus of credential shapes — the detector
    never false-positives on a value the replacer already tokenised."""

    @pytest.mark.parametrize("case", _CRED_PARITY_CORPUS)
    def test_residue_silent_on_redacter_output(self, case: dict[str, Any]) -> None:
        out, mapping = _redact(case)
        assert _residue(out, mapping) == [], (case, out)
