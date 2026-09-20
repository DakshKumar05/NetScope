"""TLS certificate inspection.

Completes a normal handshake twice: once with verification on to learn whether
the chain is trusted, once with it off to read the certificate regardless.
The second pass matters because Python returns an empty dict from
``getpeercert()`` when verification is disabled - so the certificate is taken
in DER form and parsed directly. Expired and self-signed certificates are the
cases we most want to report, and those are exactly the ones that fail
verification.

No downgrade attempts, no cipher forcing, no verification bypass beyond
reading what the server already presents publicly.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from datetime import UTC, datetime
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import ExtensionOID, NameOID

from app.config import settings
from app.core.enums import Confidence
from app.services.fingerprinting.base import ServiceDetector, ServiceInfo

TLS_PORTS = (443, 465, 636, 993, 995, 5671, 5986, 6443, 8443, 9443)

_WEAK_PROTOCOLS = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}

_NAME_FIELDS = {
    NameOID.COMMON_NAME: "commonName",
    NameOID.ORGANIZATION_NAME: "organizationName",
    NameOID.ORGANIZATIONAL_UNIT_NAME: "organizationalUnitName",
    NameOID.COUNTRY_NAME: "countryName",
    NameOID.STATE_OR_PROVINCE_NAME: "stateOrProvinceName",
    NameOID.LOCALITY_NAME: "localityName",
}


def _name_to_dict(name: x509.Name) -> dict[str, str]:
    out: dict[str, str] = {}
    for oid, label in _NAME_FIELDS.items():
        values = name.get_attributes_for_oid(oid)
        if values:
            out[label] = str(values[0].value)
    return out


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _handshake(host: str, port: int, *, verify: bool) -> dict[str, Any]:
    """Blocking TLS handshake. Returns DER bytes plus negotiated parameters."""
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    try:
        # Let older servers complete a handshake so their weakness is observable.
        context.minimum_version = ssl.TLSVersion.TLSv1
    except (ValueError, AttributeError, OSError):
        pass

    with socket.create_connection((host, port), timeout=settings.http_timeout) as raw:
        with context.wrap_socket(raw, server_hostname=host) as tls:
            cipher = tls.cipher()
            return {
                "der": tls.getpeercert(binary_form=True),
                "protocol": tls.version(),
                "cipher": cipher[0] if cipher else None,
            }


async def _handshake_async(host: str, port: int, *, verify: bool) -> dict[str, Any]:
    loop = asyncio.get_running_loop()
    return await asyncio.wait_for(
        loop.run_in_executor(None, lambda: _handshake(host, port, verify=verify)),
        timeout=settings.http_timeout + 3,
    )


def _parse_certificate(der: bytes, host: str) -> dict[str, Any]:
    cert = x509.load_der_x509_certificate(der)
    subject = _name_to_dict(cert.subject)
    issuer = _name_to_dict(cert.issuer)

    try:
        san_ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        san = list(san_ext.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        san = []

    not_before = _aware(cert.not_valid_before_utc)
    not_after = _aware(cert.not_valid_after_utc)
    now = datetime.now(UTC)

    names = {n.lower() for n in san}
    common_name = subject.get("commonName")
    if common_name:
        names.add(common_name.lower())
    hostname_match = _hostname_matches(host.lower(), names)

    try:
        fingerprint = cert.fingerprint(hashes.SHA256()).hex()
    except Exception:  # noqa: BLE001 - fingerprint is cosmetic
        fingerprint = None

    return {
        "subject": subject,
        "subject_cn": common_name,
        "issuer": issuer,
        "issuer_cn": issuer.get("commonName"),
        "san": san,
        "serial": format(cert.serial_number, "x"),
        "fingerprint_sha256": fingerprint,
        "signature_algorithm": cert.signature_algorithm_oid._name,
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "days_remaining": (not_after - now).days,
        "expired": not_after < now,
        "not_yet_valid": not_before > now,
        "self_signed": cert.subject == cert.issuer,
        "hostname_mismatch": not hostname_match,
    }


def _hostname_matches(host: str, names: set[str]) -> bool:
    if not names:
        return False
    if host in names:
        return True
    # A single leading wildcard matches exactly one label, per RFC 6125.
    for name in names:
        if name.startswith("*."):
            suffix = name[1:]
            if host.endswith(suffix) and host.count(".") == name.count("."):
                return True
    return False


class TLSDetector(ServiceDetector):
    name = "tls"
    ports = TLS_PORTS

    def handles(self, port: int, hint: str | None) -> bool:
        return port in self.ports or hint in ("https", "smtps", "ldaps", "imaps", "pop3s")

    async def detect(self, host: str, port: int) -> ServiceInfo | None:
        verified = True
        verify_error: str | None = None
        result: dict[str, Any] | None = None

        try:
            result = await _handshake_async(host, port, verify=True)
        except ssl.SSLCertVerificationError as exc:
            verified = False
            verify_error = getattr(exc, "verify_message", None) or str(exc)
        except (ssl.SSLError, OSError, asyncio.TimeoutError) as exc:
            verified = False
            verify_error = str(exc)

        if result is None:
            try:
                result = await _handshake_async(host, port, verify=False)
            except (ssl.SSLError, OSError, asyncio.TimeoutError):
                return None

        der = result.get("der")
        if not der:
            return None

        try:
            cert_details = _parse_certificate(der, host)
        except (ValueError, TypeError):
            return None

        protocol = result.get("protocol")
        details: dict[str, Any] = {
            "verified": verified,
            "verify_error": verify_error,
            "tls_version": protocol,
            "cipher": result.get("cipher"),
            "weak_protocol": protocol in _WEAK_PROTOCOLS if protocol else False,
            **cert_details,
        }

        return ServiceInfo(
            name="tls",
            product=None,
            version=protocol,
            banner=f"TLS {protocol or 'unknown'} / {cert_details.get('subject_cn') or 'no CN'}",
            confidence=Confidence.CONFIRMED,
            details=details,
        )
