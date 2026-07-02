"""Tests for the decision-record Ed25519 signer."""

from __future__ import annotations

from pathlib import Path

from soc_ai.store.signing import DecisionSigner, verify


def test_sign_verify_roundtrip(tmp_path: Path) -> None:
    signer = DecisionSigner.load_or_create(tmp_path)
    data = b'{"verdict":"false_positive"}'
    sig = signer.sign_hex(data)
    pub = signer.public_key_hex()
    assert verify(data, sig, pub) is True


def test_tamper_fails_verification(tmp_path: Path) -> None:
    signer = DecisionSigner.load_or_create(tmp_path)
    data = b'{"verdict":"false_positive"}'
    sig = signer.sign_hex(data)
    pub = signer.public_key_hex()
    # A single altered byte must fail verification.
    assert verify(b'{"verdict":"true_positive"}', sig, pub) is False


def test_wrong_key_fails_verification(tmp_path: Path) -> None:
    signer = DecisionSigner.load_or_create(tmp_path)
    other = DecisionSigner.load_or_create(tmp_path / "other")
    data = b"payload"
    assert verify(data, signer.sign_hex(data), other.public_key_hex()) is False


def test_key_is_persisted_and_stable(tmp_path: Path) -> None:
    s1 = DecisionSigner.load_or_create(tmp_path)
    pub1 = s1.public_key_hex()
    # Reloading from the same dir yields the SAME key (persisted, not regenerated).
    s2 = DecisionSigner.load_or_create(tmp_path)
    assert s2.public_key_hex() == pub1
    key_file = tmp_path / "decision_signing_ed25519.key"
    assert key_file.exists()
    assert len(key_file.read_bytes()) == 32  # raw Ed25519 seed


def test_verify_never_raises_on_garbage() -> None:
    assert verify(b"x", "not-hex", "also-not-hex") is False
    assert verify(b"x", "", "") is False
