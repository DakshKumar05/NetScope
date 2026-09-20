"""Certificate parsing.

These build real certificates in memory and parse them through the same code
path a live handshake uses. This is the area where a naive implementation
silently returns nothing: Python hands back an empty dict from
``getpeercert()`` when verification is off, which is exactly the case for the
expired and self-signed certificates most worth reporting.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from app.services.fingerprinting.tls_detector import _parse_certificate
from app.services.misconfiguration.checks import check_tls


def build_cert(
    *,
    common_name: str = "example.local",
    issuer_name: str | None = None,
    not_before: datetime | None = None,
    not_after: datetime | None = None,
    san: list[str] | None = None,
) -> bytes:
    """Return a DER-encoded certificate matching the requested shape."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    issuer = (
        subject
        if issuer_name is None
        else x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_name)])
    )
    now = datetime.now(UTC)

    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or now - timedelta(days=1))
        .not_valid_after(not_after or now + timedelta(days=365))
    )
    if san:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in san]), critical=False
        )

    cert = builder.sign(key, hashes.SHA256())
    return cert.public_bytes(serialization.Encoding.DER)


# Generating RSA keys is slow; build the fixtures once for the module.
@pytest.fixture(scope="module")
def valid_der() -> bytes:
    return build_cert(san=["example.local", "www.example.local"])


@pytest.fixture(scope="module")
def expired_der() -> bytes:
    now = datetime.now(UTC)
    return build_cert(
        not_before=now - timedelta(days=800),
        not_after=now - timedelta(days=400),
        san=["example.local"],
    )


@pytest.fixture(scope="module")
def ca_signed_der() -> bytes:
    return build_cert(issuer_name="Internal Test CA", san=["example.local"])


@pytest.fixture(scope="module")
def wildcard_der() -> bytes:
    return build_cert(common_name="*.example.local", san=["*.example.local"])


class TestParseCertificate:
    def test_reads_subject_issuer_and_validity(self, valid_der: bytes) -> None:
        details = _parse_certificate(valid_der, "example.local")
        assert details["subject_cn"] == "example.local"
        assert details["issuer_cn"] == "example.local"
        assert details["expired"] is False
        assert details["not_yet_valid"] is False
        assert details["days_remaining"] > 300

    def test_detects_self_signed(self, valid_der: bytes) -> None:
        assert _parse_certificate(valid_der, "example.local")["self_signed"] is True

    def test_ca_signed_is_not_self_signed(self, ca_signed_der: bytes) -> None:
        details = _parse_certificate(ca_signed_der, "example.local")
        assert details["self_signed"] is False
        assert details["issuer_cn"] == "Internal Test CA"

    def test_expired_certificate_is_still_fully_parsed(self, expired_der: bytes) -> None:
        """The whole point of the DER path: expired certs must not come back empty."""
        details = _parse_certificate(expired_der, "example.local")
        assert details["expired"] is True
        assert details["days_remaining"] < 0
        assert details["subject_cn"] == "example.local"
        assert details["not_after"]

    def test_reads_subject_alternative_names(self, valid_der: bytes) -> None:
        san = _parse_certificate(valid_der, "example.local")["san"]
        assert "example.local" in san
        assert "www.example.local" in san

    def test_hostname_match_from_san(self, valid_der: bytes) -> None:
        assert _parse_certificate(valid_der, "www.example.local")["hostname_mismatch"] is False

    def test_hostname_mismatch_is_reported(self, valid_der: bytes) -> None:
        assert _parse_certificate(valid_der, "other.host")["hostname_mismatch"] is True

    def test_wildcard_matches_one_label(self, wildcard_der: bytes) -> None:
        assert _parse_certificate(wildcard_der, "api.example.local")["hostname_mismatch"] is False

    def test_fingerprint_and_serial_are_present(self, valid_der: bytes) -> None:
        details = _parse_certificate(valid_der, "example.local")
        assert len(details["fingerprint_sha256"]) == 64
        assert details["serial"]
        assert "sha256" in details["signature_algorithm"].lower()

    def test_garbage_input_raises_rather_than_inventing_data(self) -> None:
        with pytest.raises(ValueError):
            _parse_certificate(b"not a certificate", "example.local")


class TestParsedCertificateFlowsIntoFindings:
    def test_expired_self_signed_cert_produces_both_findings(
        self, expired_der: bytes
    ) -> None:
        details = _parse_certificate(expired_der, "example.local")
        findings = check_tls(443, details)
        titles = " ".join(f.title for f in findings)
        assert "Expired" in titles
        assert "Self-signed" in titles

    def test_healthy_cert_produces_no_findings(self, ca_signed_der: bytes) -> None:
        details = _parse_certificate(ca_signed_der, "example.local")
        assert check_tls(443, details) == []
