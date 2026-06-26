"""Tests for the soc-ai error hierarchy."""

from __future__ import annotations

import pytest
from soc_ai.errors import (
    ApprovalRejected,
    ApprovalRequired,
    ModelError,
    OqlValidationError,
    SoApiError,
    SoAuthError,
    SocAiError,
    SoNotFoundError,
)


def test_hierarchy_roots_at_socai_error() -> None:
    for cls in (
        SoApiError,
        SoAuthError,
        SoNotFoundError,
        OqlValidationError,
        ApprovalRequired,
        ApprovalRejected,
        ModelError,
    ):
        assert issubclass(cls, SocAiError)


def test_so_api_error_carries_status_and_url() -> None:
    err = SoApiError("boom", status_code=503, url="https://so.example.com/connect/case")
    assert err.status_code == 503
    assert err.url == "https://so.example.com/connect/case"
    assert str(err) == "boom"


def test_so_auth_error_is_so_api_error() -> None:
    err = SoAuthError("credentials rejected", status_code=401)
    assert isinstance(err, SoApiError)
    assert err.status_code == 401


def test_oql_validation_error_carries_fragment() -> None:
    err = OqlValidationError("unknown field 'bogus.field'", fragment="bogus.field")
    assert err.fragment == "bogus.field"


def test_approval_required_carries_tool_args_token() -> None:
    err = ApprovalRequired("ack_alert", {"alert_id": "abc"}, "tok-1")
    assert err.tool_name == "ack_alert"
    assert err.tool_args == {"alert_id": "abc"}
    assert err.token == "tok-1"
    assert "ack_alert" in str(err)


def test_approval_rejected_carries_reason() -> None:
    err = ApprovalRejected("escalate_to_case", reason="insufficient evidence")
    assert err.tool_name == "escalate_to_case"
    assert err.reason == "insufficient evidence"
    assert "insufficient evidence" in str(err)


def test_approval_rejected_without_reason() -> None:
    err = ApprovalRejected("ack_alert")
    assert err.reason is None
    assert "rejected ack_alert" in str(err)


def test_model_error_is_socai_error() -> None:
    with pytest.raises(SocAiError):
        raise ModelError("LiteLLM 502")
