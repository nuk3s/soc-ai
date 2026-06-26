"""Fernet encryption for secret config overrides stored at rest.

Secret Danger-Zone settings (SO/ES passwords, the LiteLLM key, the crawl4ai
token) are persisted in the ``config_overrides`` table as Fernet ciphertext, not
plaintext. The key comes from ``settings.config_secret_key`` (env
``CONFIG_SECRET_KEY``) — the only plaintext secret, living in ``.env`` exactly
like every other credential. This protects against DB-only exposure: a config-DB
backup, an accidental commit, or a SQL dump never reveals a live secret.

If no (valid) key is configured the box is unavailable; the route layer then
refuses to persist secret values (connection identity stays editable).
"""

from __future__ import annotations

import logging
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

_LOGGER = logging.getLogger(__name__)


class SecretBox:
    """Symmetric encrypt/decrypt for at-rest secret config values."""

    def __init__(self, key: str) -> None:
        # Raises ValueError on a malformed key — callers use make_secret_box,
        # which catches it and returns None (box unavailable).
        self._fernet = Fernet(key.encode())

    def encrypt(self, plaintext: str) -> str:
        return self._fernet.encrypt(plaintext.encode()).decode()

    def decrypt(self, token: str) -> str:
        """Decrypt a stored token. Raises ValueError on a tampered/foreign token
        (e.g. the key was rotated) so the caller can skip that override rather
        than crash."""
        try:
            return self._fernet.decrypt(token.encode()).decode()
        except InvalidToken as exc:  # pragma: no cover - defensive
            raise ValueError("secret override could not be decrypted (key changed?)") from exc


def make_secret_box(settings: Any) -> SecretBox | None:
    """Build a :class:`SecretBox` from ``settings.config_secret_key`` or None.

    Returns None (with a one-time log) when the key is unset or malformed — the
    Danger Zone then keeps secret VALUES read-only while identity stays editable.
    """
    raw = getattr(settings, "config_secret_key", None)
    if raw is None:
        return None
    key = raw.get_secret_value() if hasattr(raw, "get_secret_value") else str(raw)
    if not key:
        return None
    try:
        return SecretBox(key)
    except (ValueError, TypeError) as exc:
        _LOGGER.warning(
            "CONFIG_SECRET_KEY is set but invalid (%s) — secret editing disabled; "
            'generate one with: python -c "from cryptography.fernet import Fernet; '
            'print(Fernet.generate_key().decode())"',
            exc,
        )
        return None
