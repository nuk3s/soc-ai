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
    """Run the independent residue sweep exactly as the client does."""
    payload = json.dumps(sanitized)
    return unsafe_residue(payload, known_values=tuple(mapping.reverse.values()))


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
        import time

        case = {
            "message": "user=" + ("a-" * 20000),
            "payload_printable": ("z-" * 20000) + " end",
            "rule_name": ("w." * 20000) + "x",
        }
        start = time.perf_counter()
        mapping = Mapping()
        out = sanitize_case(case, mapping)
        unsafe_residue(json.dumps(out), known_values=tuple(mapping.reverse.values()))
        elapsed = time.perf_counter() - start
        # Pre-fix this took multiple seconds (catastrophic backtracking).
        assert elapsed < 1.5, f"redaction took {elapsed:.2f}s — possible ReDoS regression"

    def test_real_suffix_fqdn_still_redacted(self) -> None:
        # The bound must not break matching of a normal internal FQDN.
        out, _ = _redact({"message": "beacon from dc01.ad.lan internal"})
        assert "dc01.ad.lan" not in out["message"]
        assert "HOST_01" in out["message"]

    def test_real_internal_email_still_redacted(self) -> None:
        out, _ = _redact({"message": "from admin@corp.lan today"})
        assert "admin@corp.lan" not in out["message"]
        assert "EMAIL_01" in out["message"]
