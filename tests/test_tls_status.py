"""The certificate inspector: what soc-ai says about the files it serves with."""

from __future__ import annotations

import datetime as dt
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.x509.oid import NameOID
from soc_ai.tls_status import describe, inspect_tls

NOW = dt.datetime(2026, 9, 29, 12, 0, tzinfo=dt.UTC)

PrivateKey = ec.EllipticCurvePrivateKey | rsa.RSAPrivateKey | ed25519.Ed25519PrivateKey


def _key() -> ec.EllipticCurvePrivateKey:
    return ec.generate_private_key(ec.SECP256R1())


def _pem_key(key: PrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def _cert(
    *,
    subject: str,
    issuer_name: str,
    issuer_key: PrivateKey,
    key: PrivateKey,
    days: int,
    sans: tuple[str, ...] = (),
    ca: bool = False,
    not_before: dt.datetime | None = None,
) -> x509.Certificate:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject)])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)])
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or (NOW - dt.timedelta(days=400)))
        .not_valid_after(NOW + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False
        )
    algorithm = None if isinstance(issuer_key, ed25519.Ed25519PrivateKey) else hashes.SHA256()
    return builder.sign(issuer_key, algorithm)


def _write(tmp_path: Path, certs: list[x509.Certificate], key: PrivateKey) -> tuple[Path, Path]:
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs))
    key_path.write_bytes(_pem_key(key))
    return cert_path, key_path


def _self_signed(tmp_path: Path, key: PrivateKey, days: int, **extra: Any) -> tuple[Path, Path]:
    cert = _cert(
        subject="soc-ai.example.test",
        issuer_name="soc-ai.example.test",
        issuer_key=key,
        key=key,
        days=days,
        **extra,
    )
    return _write(tmp_path, [cert], key)


def _assert_sentences(lines: list[str]) -> None:
    """Every line a person reads starts with a capital letter and ends with a period."""
    for line in lines:
        assert line[0].isupper(), line
        assert line.endswith("."), line
        assert ".." not in line, line


def test_a_self_signed_pair_reads_as_self_signed_with_its_names_and_days(tmp_path: Path) -> None:
    key = _key()
    cert = _cert(
        subject="soc-ai.example.test",
        issuer_name="soc-ai.example.test",
        issuer_key=key,
        key=key,
        days=200,
        sans=("soc-ai.example.test",),
    )
    cert_path, key_path = _write(tmp_path, [cert], key)
    status = inspect_tls(cert_path, key_path, now=NOW)
    assert status.mode == "direct"
    assert status.subject == "CN=soc-ai.example.test"
    assert status.self_signed is True
    assert status.key_matches is True
    assert status.chain_length == 1
    assert status.sans == ["soc-ai.example.test"]
    assert status.days_left == 200
    assert status.errors == []
    assert status.warnings == ["The certificate is self-signed. Browsers warn on it."]


def test_a_ca_signed_chain_in_order_reads_as_a_valid_chain(tmp_path: Path) -> None:
    ca_key, leaf_key = _key(), _key()
    ca = _cert(
        subject="Example CA",
        issuer_name="Example CA",
        issuer_key=ca_key,
        key=ca_key,
        days=3650,
        ca=True,
    )
    leaf = _cert(
        subject="soc-ai.example.test",
        issuer_name="Example CA",
        issuer_key=ca_key,
        key=leaf_key,
        days=90,
    )
    cert_path, key_path = _write(tmp_path, [leaf, ca], leaf_key)
    status = inspect_tls(cert_path, key_path, now=NOW)
    assert status.self_signed is False
    assert status.chain_length == 2
    assert status.chain_ok is True
    assert status.issuer == "CN=Example CA"
    assert status.warnings == []
    assert status.errors == []


def test_a_chain_out_of_order_is_a_warning(tmp_path: Path) -> None:
    ca_key, leaf_key = _key(), _key()
    ca = _cert(
        subject="Example CA",
        issuer_name="Example CA",
        issuer_key=ca_key,
        key=ca_key,
        days=3650,
        ca=True,
    )
    leaf = _cert(
        subject="soc-ai.example.test",
        issuer_name="Example CA",
        issuer_key=ca_key,
        key=leaf_key,
        days=90,
    )
    cert_path, key_path = _write(tmp_path, [ca, leaf], leaf_key)
    status = inspect_tls(cert_path, key_path, now=NOW)
    assert status.chain_ok is False
    assert any("out of order or incomplete" in w for w in status.warnings)
    _assert_sentences(status.warnings)


def test_a_key_that_does_not_match_is_an_error(tmp_path: Path) -> None:
    key, other = _key(), _key()
    cert = _cert(
        subject="soc-ai.example.test",
        issuer_name="soc-ai.example.test",
        issuer_key=key,
        key=key,
        days=90,
    )
    cert_path, key_path = _write(tmp_path, [cert], other)
    status = inspect_tls(cert_path, key_path, now=NOW)
    assert status.key_matches is False
    assert status.errors == ["The key does not match the certificate."]


@pytest.mark.parametrize(
    "make_key",
    [
        pytest.param(lambda: ec.generate_private_key(ec.SECP256R1()), id="ecdsa-pkcs8"),
        pytest.param(lambda: rsa.generate_private_key(65537, 2048), id="rsa-pkcs8"),
        pytest.param(ed25519.Ed25519PrivateKey.generate, id="ed25519"),
    ],
)
def test_key_matches_for_every_key_type(tmp_path: Path, make_key: Any) -> None:
    key = make_key()
    cert_path, key_path = _self_signed(tmp_path, key, days=90)
    status = inspect_tls(cert_path, key_path, now=NOW)
    assert status.key_matches is True
    assert status.errors == []


def test_expiry_bands(tmp_path: Path) -> None:
    key = _key()
    for days, band in ((40, None), (30, 30), (14, 14), (7, 7), (-1, 0)):
        cert_path, key_path = _self_signed(tmp_path, key, days=days)
        status = inspect_tls(cert_path, key_path, now=NOW)
        assert status.expiry_band == band, days
    assert status.expired is True
    assert any("expired" in e for e in status.errors)


@pytest.mark.parametrize(
    ("days", "band"),
    [(31, None), (30, 30), (15, 30), (14, 14), (8, 14), (7, 7), (1, 7), (0, 7), (-1, 0)],
)
def test_expiry_band_boundaries(tmp_path: Path, days: int, band: int | None) -> None:
    key = _key()
    cert_path, key_path = _self_signed(tmp_path, key, days=days)
    status = inspect_tls(cert_path, key_path, now=NOW)
    assert status.expiry_band == band
    _assert_sentences(status.warnings)
    _assert_sentences(status.errors)


def test_expiry_wording_counts_days_and_dates(tmp_path: Path) -> None:
    key = _key()
    cert_path, key_path = _self_signed(tmp_path, key, days=1)
    status = inspect_tls(cert_path, key_path, now=NOW)
    assert "The certificate expires in 1 day." in status.warnings
    cert_path, key_path = _self_signed(tmp_path, key, days=5)
    status = inspect_tls(cert_path, key_path, now=NOW)
    assert "The certificate expires in 5 days." in status.warnings
    cert_path, key_path = _self_signed(tmp_path, key, days=-2)
    status = inspect_tls(cert_path, key_path, now=NOW)
    assert status.errors == ["The certificate expired on 2026-09-27."]


def test_a_certificate_that_is_not_yet_valid_is_an_error(tmp_path: Path) -> None:
    key = _key()
    cert_path, key_path = _self_signed(
        tmp_path, key, days=90, not_before=NOW + dt.timedelta(days=3)
    )
    status = inspect_tls(cert_path, key_path, now=NOW)
    assert "The certificate is not valid until 2026-10-02." in status.errors
    assert status.key_matches is True


def test_an_oversize_file_is_refused_without_a_read(tmp_path: Path) -> None:
    key = _key()
    cert_path, key_path = _self_signed(tmp_path, key, days=90)
    cert_path.write_bytes(b"x" * (300 * 1024))
    status = inspect_tls(cert_path, key_path, now=NOW)
    assert status.errors == [
        f"The file {cert_path} is 307200 bytes. A PEM chain is a few kilobytes."
    ]
    assert status.fingerprint_sha256 is None


def test_a_missing_file_is_an_error_not_an_exception(tmp_path: Path) -> None:
    status = inspect_tls(tmp_path / "none.pem", tmp_path / "none-key.pem", now=NOW)
    assert status.mode == "direct"
    assert status.errors and status.errors[0].startswith("Cannot read the certificate file")
    assert status.days_left is None
    _assert_sentences(status.errors)


def test_a_file_that_is_not_pem_is_an_error_sentence(tmp_path: Path) -> None:
    key = _key()
    cert_path, key_path = _self_signed(tmp_path, key, days=90)
    cert_path.write_bytes(b"not a certificate")
    status = inspect_tls(cert_path, key_path, now=NOW)
    assert status.errors and "is not PEM" in status.errors[0]
    _assert_sentences(status.errors)
    key_path.write_bytes(b"not a key")
    cert_path, _ = _self_signed(tmp_path, key, days=90)
    key_path.write_bytes(b"not a key")
    status = inspect_tls(cert_path, key_path, now=NOW)
    assert status.errors and "is not a PEM private key" in status.errors[0]
    _assert_sentences(status.errors)


def test_a_surprise_in_the_parser_is_an_error_not_an_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = _key()
    cert_path, key_path = _self_signed(tmp_path, key, days=90)

    def boom(_data: bytes) -> list[x509.Certificate]:
        raise RuntimeError("the parser fell over")

    monkeypatch.setattr("soc_ai.tls_status.x509.load_pem_x509_certificates", boom)
    status = inspect_tls(cert_path, key_path, now=NOW)
    assert status.errors == ["Cannot inspect the certificate: the parser fell over."]


def test_describe_joins_the_errors_with_a_space(tmp_path: Path) -> None:
    key, other = _key(), _key()
    cert = _cert(
        subject="soc-ai.example.test",
        issuer_name="soc-ai.example.test",
        issuer_key=key,
        key=key,
        days=-2,
    )
    cert_path, key_path = _write(tmp_path, [cert], other)
    status = inspect_tls(cert_path, key_path, now=NOW)
    assert describe(status) == (
        "The certificate expired on 2026-09-27. The key does not match the certificate."
    )


def test_tls_off_reads_as_off() -> None:
    status = inspect_tls(None, None, now=NOW)
    assert status.mode == "off"
    assert status.errors == [] and status.warnings == []
