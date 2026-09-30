"""What soc-ai says about the certificate and the key it serves with.

One record for every reader: the start log, the doctor, the ``/config/tls``
route, the expiry loop and the Config panel. The inspector reads the files
on disk now. soc-ai loads the files once at start, so a caller that wants to
know whether a restart is due compares two fingerprints.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from itertools import pairwise
from pathlib import Path
from typing import Literal

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

EXPIRY_BANDS: tuple[int, ...] = (30, 14, 7)
"""Days-left thresholds. The band is the smallest threshold at or above days left."""

MAX_PEM_BYTES = 262144
"""The inspector refuses a file above this size. A PEM chain is a few kilobytes."""

TlsMode = Literal["direct", "off"]


@dataclass
class TlsStatus:
    mode: TlsMode
    cert_path: str | None = None
    key_path: str | None = None
    subject: str | None = None
    issuer: str | None = None
    sans: list[str] = field(default_factory=list)
    not_before: str | None = None
    not_after: str | None = None
    days_left: int | None = None
    expired: bool = False
    expiry_band: int | None = None
    self_signed: bool = False
    chain_length: int = 0
    chain_ok: bool = True
    key_matches: bool | None = None
    fingerprint_sha256: str | None = None
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, object]:
        return {
            "mode": self.mode,
            "cert_path": self.cert_path,
            "key_path": self.key_path,
            "subject": self.subject,
            "issuer": self.issuer,
            "sans": list(self.sans),
            "not_before": self.not_before,
            "not_after": self.not_after,
            "days_left": self.days_left,
            "expired": self.expired,
            "expiry_band": self.expiry_band,
            "self_signed": self.self_signed,
            "chain_length": self.chain_length,
            "chain_ok": self.chain_ok,
            "key_matches": self.key_matches,
            "fingerprint_sha256": self.fingerprint_sha256,
            "warnings": list(self.warnings),
            "errors": list(self.errors),
        }


def expiry_band(days_left: int) -> int | None:
    """The expiry band for *days_left*: 0 when expired, else the tightest threshold met."""
    if days_left < 0:
        return 0
    band: int | None = None
    for threshold in EXPIRY_BANDS:
        if days_left <= threshold:
            band = threshold
    return band


def days_left_at(not_after: str | dt.datetime, when: dt.datetime) -> int:
    """Whole days from *when* to *not_after*. Minus one once the certificate has expired."""
    end = dt.datetime.fromisoformat(not_after) if isinstance(not_after, str) else not_after
    remaining = end - when
    if remaining.total_seconds() < 0:
        return -1
    return remaining.days


def _sentence(text: str) -> str:
    """One sentence: the text with its trailing space and period trimmed, plus a period."""
    return text.rstrip().rstrip(".") + "."


def _sans(cert: x509.Certificate) -> list[str]:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
    except x509.ExtensionNotFound:
        return []
    names: list[str] = []
    names.extend(ext.value.get_values_for_type(x509.DNSName))
    names.extend(str(ip) for ip in ext.value.get_values_for_type(x509.IPAddress))
    return names


def _read_pem(path: Path, what: str, status: TlsStatus) -> bytes | None:
    """The bytes of a small PEM file, or None with the reason in ``status.errors``."""
    try:
        size = path.stat().st_size
        if size > MAX_PEM_BYTES:
            status.errors.append(
                f"The file {path} is {size} bytes. A PEM chain is a few kilobytes."
            )
            return None
        return path.read_bytes()
    except OSError as exc:
        status.errors.append(
            _sentence(f"Cannot read the {what} file {path}: {exc.strerror or exc}")
        )
        return None


def _inspect(status: TlsStatus, cert_path: Path, key_path: Path, when: dt.datetime) -> None:
    cert_bytes = _read_pem(cert_path, "certificate", status)
    if cert_bytes is None:
        return
    try:
        certs = x509.load_pem_x509_certificates(cert_bytes)
    except ValueError as exc:
        status.errors.append(_sentence(f"The certificate file {cert_path} is not PEM: {exc}"))
        return
    leaf = certs[0]
    status.chain_length = len(certs)
    status.subject = leaf.subject.rfc4514_string()
    status.issuer = leaf.issuer.rfc4514_string()
    status.sans = _sans(leaf)
    status.not_before = leaf.not_valid_before_utc.isoformat()
    status.not_after = leaf.not_valid_after_utc.isoformat()
    status.fingerprint_sha256 = leaf.fingerprint(hashes.SHA256()).hex()
    status.self_signed = leaf.subject == leaf.issuer
    status.days_left = days_left_at(leaf.not_valid_after_utc, when)
    status.expired = status.days_left < 0
    status.expiry_band = expiry_band(status.days_left)
    if status.expired:
        status.errors.append(f"The certificate expired on {status.not_after[:10]}.")
    elif status.expiry_band is not None:
        unit = "day" if status.days_left == 1 else "days"
        status.warnings.append(f"The certificate expires in {status.days_left} {unit}.")
    if leaf.not_valid_before_utc > when:
        status.errors.append(f"The certificate is not valid until {status.not_before[:10]}.")
    if status.self_signed:
        status.warnings.append("The certificate is self-signed. Browsers warn on it.")
    for upper, lower in pairwise(certs):
        if upper.issuer != lower.subject:
            status.chain_ok = False
            status.warnings.append(
                "The chain is out of order or incomplete. The leaf comes first, then each issuer."
            )
            break
    key_bytes = _read_pem(key_path, "key", status)
    if key_bytes is None:
        return
    try:
        key = serialization.load_pem_private_key(key_bytes, password=None)
    except (ValueError, TypeError) as exc:
        status.errors.append(_sentence(f"The key file {key_path} is not a PEM private key: {exc}"))
        return
    spki = serialization.PublicFormat.SubjectPublicKeyInfo
    enc = serialization.Encoding.DER
    status.key_matches = key.public_key().public_bytes(enc, spki) == leaf.public_key().public_bytes(
        enc, spki
    )
    if not status.key_matches:
        status.errors.append("The key does not match the certificate.")


def inspect_tls(
    cert_path: Path | str | None,
    key_path: Path | str | None,
    *,
    now: dt.datetime | None = None,
) -> TlsStatus:
    """Inspect the certificate file and the key file. Never raises."""
    if not cert_path or not key_path:
        return TlsStatus(mode="off")
    when = now or dt.datetime.now(dt.UTC)
    status = TlsStatus(mode="direct", cert_path=str(cert_path), key_path=str(key_path))
    try:
        _inspect(status, Path(cert_path), Path(key_path), when)
    except Exception as exc:  # a surprise in the parser must not stop soc-ai
        status.errors.append(_sentence(f"Cannot inspect the certificate: {exc}"))
    return status


def describe(status: TlsStatus) -> str:
    """One line for the start log and the doctor."""
    if status.mode == "off":
        return "off. soc-ai serves plain HTTP."
    if status.errors:
        return " ".join(status.errors)
    if status.days_left is None:
        days = "unknown"
    else:
        days = f"{status.days_left} day" if status.days_left == 1 else f"{status.days_left} days"
    kind = "self-signed" if status.self_signed else f"issued by {status.issuer}"
    return f"{status.subject}, {kind}, expires in {days}."
