"""Ed25519 detached-signature signer for decision-record exports.

An exported decision record carries a sha256 checksum (accidental-corruption
detection) AND — when a signing key is available — an Ed25519 detached signature
over the same canonical bytes. Unlike the checksum, the signature is
tamper-EVIDENT: an external auditor verifies it with the published public key
alone (no server secret), so a record altered after export fails verification.

The private key is a raw 32-byte Ed25519 seed stored 0600 at
``<soc_ai_data_dir>/decision_signing_ed25519.key``, generated on first use. The
public key is published (an API endpoint + embedded in every export) for
verification. Losing/rotating the key only invalidates OLD signatures — the
checksum still detects corruption regardless.
"""

from __future__ import annotations

import logging
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

_LOGGER = logging.getLogger(__name__)
_KEY_FILENAME = "decision_signing_ed25519.key"


class DecisionSigner:
    """Signs decision-record bytes with a persistent Ed25519 key."""

    def __init__(self, private_key: Ed25519PrivateKey) -> None:
        self._sk = private_key

    @classmethod
    def load_or_create(cls, data_dir: Path) -> DecisionSigner:
        """Load the signing key from *data_dir*, generating + persisting one if absent."""
        path = Path(data_dir) / _KEY_FILENAME
        if path.exists():
            return cls(Ed25519PrivateKey.from_private_bytes(path.read_bytes()))
        sk = Ed25519PrivateKey.generate()
        seed = sk.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(seed)
        try:
            path.chmod(0o600)
        except OSError:  # pragma: no cover - best-effort on exotic filesystems
            _LOGGER.warning("could not chmod 0600 the decision signing key at %s", path)
        _LOGGER.info("generated decision-record signing key at %s", path)
        return cls(sk)

    def sign_hex(self, data: bytes) -> str:
        """Detached Ed25519 signature over *data*, hex-encoded."""
        return self._sk.sign(data).hex()

    def public_key_hex(self) -> str:
        """The verification public key (raw Ed25519), hex-encoded."""
        raw = self._sk.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        return raw.hex()


def verify(data: bytes, signature_hex: str, public_key_hex: str) -> bool:
    """True iff *signature_hex* is a valid Ed25519 signature over *data* under
    *public_key_hex*. Never raises — a malformed input returns False."""
    try:
        pk = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        pk.verify(bytes.fromhex(signature_hex), data)
    except Exception:
        return False
    return True
