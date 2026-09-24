def test_model_battery_is_a_declared_audit_kind() -> None:
    """It was used at a call site and absent from the literal, so every write raised.

    `routes_config.py` logs `kind="model_battery"` inside a try/except that
    exists so an audit failure cannot fail a completed battery. The kind was
    never in `AuditKind`, so `AuditEvent` construction raised a ValidationError
    every time and the except swallowed it: the battery ran, the audit trail
    silently did not.
    """
    import typing
    from datetime import UTC, datetime

    from soc_ai.audit.schemas import AuditEvent, AuditKind

    assert "model_battery" in typing.get_args(AuditKind)
    AuditEvent(
        session_id="model-battery:x",
        user="u",
        approved_by=None,
        timestamp=datetime.now(UTC),
        kind="model_battery",
        payload={},
    )
