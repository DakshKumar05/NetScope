"""Non-destructive misconfiguration checks.

Every check here reads state the service already exposes to any client. None
of them authenticate, guess credentials, enumerate directories, or alter
anything on the target. Where a real answer would require credentials, the
check reports that a manual review is needed instead of guessing.
"""

from __future__ import annotations

import asyncio
import contextlib

from app.config import settings
from app.core.enums import Confidence, FindingType, Protocol, Severity
from app.core.findings import FindingDraft
from app.services.fingerprinting.base import ServiceInfo

# Services that expose data or administrative control if reachable broadly.
SENSITIVE_SERVICES: dict[int, tuple[str, str]] = {
    23: ("Telnet", "Telnet carries credentials and session data in cleartext."),
    445: ("SMB", "SMB exposes file shares and is a common lateral-movement path."),
    1433: ("Microsoft SQL Server", "Database engines should not be reachable broadly."),
    1521: ("Oracle Database", "Database engines should not be reachable broadly."),
    3306: ("MySQL/MariaDB", "Database engines should not be reachable broadly."),
    3389: ("RDP", "RDP is a frequent target of credential-based attacks."),
    5432: ("PostgreSQL", "Database engines should not be reachable broadly."),
    5900: ("VNC", "VNC often ships with weak or absent authentication."),
    6379: ("Redis", "Redis historically defaults to no authentication."),
    9200: ("Elasticsearch", "Elasticsearch HTTP APIs often lack authentication."),
    11211: ("Memcached", "Memcached has no authentication and is abusable for amplification."),
    27017: ("MongoDB", "MongoDB has historically shipped without authentication."),
}

# Services where the only honest answer is "a human must check this".
CREDENTIAL_REVIEW_PORTS = {23, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017}


def check_exposed_service(port: int, protocol: str, service: ServiceInfo) -> list[FindingDraft]:
    label = service.product or service.name or "Unknown service"
    version = f" {service.version}" if service.version else ""
    findings = [
        FindingDraft(
            type=FindingType.EXPOSED_SERVICE,
            severity=Severity.INFO,
            title=f"{label}{version} reachable on port {port}/{protocol}",
            reason="The port accepted a connection, so the service is reachable from this scanner.",
            evidence=service.banner or f"Connection to {port}/{protocol} succeeded.",
            recommendation=(
                "Confirm this service is intended to be reachable from this network segment. "
                "If not, restrict it with a firewall rule or bind it to a loopback interface."
            ),
            confidence=Confidence.CONFIRMED,
            port=port,
            protocol=protocol,
        )
    ]

    if port in SENSITIVE_SERVICES and protocol == Protocol.TCP:
        name, rationale = SENSITIVE_SERVICES[port]
        findings.append(
            FindingDraft(
                type=FindingType.SENSITIVE_SERVICE,
                severity=Severity.MEDIUM,
                title=f"Sensitive service exposed: {name} on port {port}",
                reason=(
                    f"Port {port} is associated with {name}. {rationale} Exposure alone is the "
                    "finding here - no authentication weakness has been tested or claimed."
                ),
                evidence=service.banner or f"Port {port}/tcp is open.",
                recommendation=(
                    f"Restrict {name} to trusted source ranges, require authentication, and "
                    "prefer an encrypted transport or a VPN/bastion for remote access."
                ),
                confidence=Confidence.CONFIRMED,
                port=port,
                protocol=protocol,
            )
        )

    if port in CREDENTIAL_REVIEW_PORTS and protocol == Protocol.TCP:
        findings.append(
            FindingDraft(
                type=FindingType.CREDENTIAL_REVIEW,
                severity=Severity.INFO,
                title=f"Credential configuration should be reviewed manually on port {port}",
                reason=(
                    "This service class is commonly deployed with default or absent credentials. "
                    "This scanner does not test credentials, so this is a prompt for review, "
                    "not evidence of a weakness."
                ),
                evidence=f"Service class on port {port} commonly requires credential review.",
                recommendation=(
                    "Verify that authentication is enabled, that no vendor default account "
                    "remains active, and that passwords meet your policy."
                ),
                confidence=Confidence.POSSIBLE,
                port=port,
                protocol=protocol,
            )
        )

    return findings


async def check_anonymous_ftp(host: str, port: int) -> FindingDraft | None:
    """Ask the FTP server whether anonymous login is accepted.

    This sends the RFC-959 anonymous login that public FTP servers are designed
    to accept. It is a single, standard request - not password guessing - and
    the connection is closed immediately afterwards.
    """
    reader = writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=settings.http_timeout
        )
        greeting = await asyncio.wait_for(reader.readline(), timeout=settings.http_timeout)
        if not greeting.startswith(b"220"):
            return None

        writer.write(b"USER anonymous\r\n")
        await asyncio.wait_for(writer.drain(), timeout=settings.http_timeout)
        user_reply = await asyncio.wait_for(reader.readline(), timeout=settings.http_timeout)

        if not user_reply.startswith((b"331", b"230")):
            return None

        if user_reply.startswith(b"331"):
            writer.write(b"PASS anonymous@example.com\r\n")
            await asyncio.wait_for(writer.drain(), timeout=settings.http_timeout)
            pass_reply = await asyncio.wait_for(reader.readline(), timeout=settings.http_timeout)
        else:
            pass_reply = user_reply

        with contextlib.suppress(Exception):
            writer.write(b"QUIT\r\n")
            await writer.drain()

        if not pass_reply.startswith(b"230"):
            return None

        detail = pass_reply.decode("utf-8", errors="replace").strip()
        return FindingDraft(
            type=FindingType.FTP_ISSUE,
            severity=Severity.HIGH,
            title=f"Anonymous FTP login accepted on port {port}",
            reason=(
                "The server accepted the anonymous account, so any client on this network can "
                "list and retrieve whatever that account can reach, without credentials."
            ),
            evidence=f"Server replied: {detail}",
            recommendation=(
                "Disable anonymous access unless this is a deliberate public file drop. "
                "If it is deliberate, confirm the anonymous root is read-only and contains "
                "nothing sensitive, and prefer HTTPS or SFTP for anything else."
            ),
            confidence=Confidence.CONFIRMED,
            port=port,
            protocol=Protocol.TCP,
        )
    except (asyncio.TimeoutError, OSError):
        return None
    finally:
        if writer is not None:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()


def check_tls(port: int, tls: dict) -> list[FindingDraft]:
    findings: list[FindingDraft] = []
    subject = tls.get("subject_cn") or "unknown subject"
    issuer = tls.get("issuer_cn") or "unknown issuer"
    not_after = tls.get("not_after")

    if tls.get("expired"):
        findings.append(
            FindingDraft(
                type=FindingType.TLS_ISSUE,
                severity=Severity.HIGH,
                title=f"Expired TLS certificate on port {port}",
                reason=(
                    "An expired certificate makes genuine warnings indistinguishable from an "
                    "interception attempt, and trains users to click through them."
                ),
                evidence=f"Certificate for '{subject}' expired at {not_after}.",
                recommendation="Renew the certificate and automate renewal (for example, ACME).",
                confidence=Confidence.CONFIRMED,
                port=port,
                protocol=Protocol.TCP,
            )
        )
    elif isinstance(tls.get("days_remaining"), int) and 0 <= tls["days_remaining"] <= 21:
        findings.append(
            FindingDraft(
                type=FindingType.TLS_ISSUE,
                severity=Severity.LOW,
                title=f"TLS certificate expires in {tls['days_remaining']} days on port {port}",
                reason="A certificate close to expiry will cause an outage if renewal is missed.",
                evidence=f"Certificate for '{subject}' is valid until {not_after}.",
                recommendation="Renew ahead of expiry and verify that automated renewal works.",
                confidence=Confidence.CONFIRMED,
                port=port,
                protocol=Protocol.TCP,
            )
        )

    if tls.get("not_yet_valid"):
        findings.append(
            FindingDraft(
                type=FindingType.TLS_ISSUE,
                severity=Severity.MEDIUM,
                title=f"TLS certificate is not yet valid on port {port}",
                reason=(
                    "The certificate's validity period starts in the future, which usually means "
                    "a misissued certificate or a clock problem on the server."
                ),
                evidence=f"Certificate for '{subject}' is valid from {tls.get('not_before')}.",
                recommendation="Check the server clock and reissue the certificate if needed.",
                confidence=Confidence.CONFIRMED,
                port=port,
                protocol=Protocol.TCP,
            )
        )

    if tls.get("self_signed"):
        findings.append(
            FindingDraft(
                type=FindingType.TLS_ISSUE,
                severity=Severity.MEDIUM,
                title=f"Self-signed TLS certificate on port {port}",
                reason=(
                    "A self-signed certificate is not anchored to any trusted authority, so "
                    "clients cannot distinguish the real server from an impostor."
                ),
                evidence=f"Subject and issuer are identical: '{subject}'.",
                recommendation=(
                    "Issue the certificate from a CA your clients trust. An internal CA is "
                    "fine for internal services, provided its root is distributed."
                ),
                confidence=Confidence.CONFIRMED,
                port=port,
                protocol=Protocol.TCP,
            )
        )

    if tls.get("hostname_mismatch") and not tls.get("self_signed"):
        findings.append(
            FindingDraft(
                type=FindingType.TLS_ISSUE,
                severity=Severity.MEDIUM,
                title=f"TLS certificate hostname mismatch on port {port}",
                reason=(
                    "The name being connected to does not appear in the certificate's subject "
                    "or SAN list, so strict clients will refuse the connection."
                ),
                evidence=(
                    f"Certificate names: {', '.join(tls.get('san') or []) or subject}; "
                    f"issued by '{issuer}'."
                ),
                recommendation=(
                    "Reissue the certificate with the hostname clients actually use in its SAN."
                ),
                confidence=Confidence.PROBABLE,
                port=port,
                protocol=Protocol.TCP,
            )
        )

    if tls.get("weak_protocol"):
        findings.append(
            FindingDraft(
                type=FindingType.TLS_ISSUE,
                severity=Severity.HIGH,
                title=f"Obsolete TLS version negotiated on port {port}: {tls.get('tls_version')}",
                reason=(
                    "TLS 1.0 and 1.1 are deprecated and carry known cryptographic weaknesses. "
                    "The server negotiated one when offered, so it still permits it."
                ),
                evidence=f"Negotiated {tls.get('tls_version')} using cipher {tls.get('cipher')}.",
                recommendation="Require TLS 1.2 as a minimum, and prefer TLS 1.3.",
                confidence=Confidence.CONFIRMED,
                port=port,
                protocol=Protocol.TCP,
            )
        )

    return findings


def check_http(port: int, details: dict) -> list[FindingDraft]:
    findings: list[FindingDraft] = []
    scheme = details.get("scheme")
    url = details.get("url", "")
    status = details.get("status_code")

    if scheme == "http":
        findings.append(
            FindingDraft(
                type=FindingType.HTTP_ISSUE,
                severity=Severity.MEDIUM,
                title=f"Unencrypted HTTP service on port {port}",
                reason=(
                    "Traffic to this service is not encrypted, so credentials, session cookies "
                    "and page content are readable by anyone on the path."
                ),
                evidence=f"{url} responded with HTTP {status} over cleartext.",
                recommendation=(
                    "Serve over HTTPS and redirect HTTP to it, then enable HSTS once the "
                    "redirect is confirmed working."
                ),
                confidence=Confidence.CONFIRMED,
                port=port,
                protocol=Protocol.TCP,
            )
        )

    missing = details.get("missing_security_headers") or []
    if missing and status and 200 <= int(status) < 400:
        findings.append(
            FindingDraft(
                type=FindingType.HTTP_ISSUE,
                severity=Severity.LOW,
                title=f"Missing HTTP security headers on port {port}",
                reason=(
                    "These response headers are defence-in-depth controls. Their absence is not "
                    "itself an exploit, but it removes browser-side protection against "
                    "clickjacking, MIME sniffing and injected content."
                ),
                evidence=f"Absent headers: {', '.join(missing)}.",
                recommendation=(
                    "Add Content-Security-Policy, X-Content-Type-Options: nosniff, "
                    "X-Frame-Options (or CSP frame-ancestors), Referrer-Policy, and "
                    "Strict-Transport-Security on HTTPS origins."
                ),
                confidence=Confidence.CONFIRMED,
                port=port,
                protocol=Protocol.TCP,
            )
        )

    admin = details.get("admin_interface")
    if admin:
        requires_auth = details.get("requires_auth")
        severity = Severity.MEDIUM if requires_auth else Severity.HIGH
        findings.append(
            FindingDraft(
                type=FindingType.ADMIN_INTERFACE,
                severity=severity,
                title=f"{admin} administrative interface reachable on port {port}",
                reason=(
                    f"The response identifies {admin}, an administrative interface. "
                    + (
                        "It returned an authentication challenge, so it is at least gated."
                        if requires_auth
                        else "It returned content without an authentication challenge, so some "
                        "of it is readable unauthenticated."
                    )
                    + " No login was attempted."
                ),
                evidence=(
                    f"{url} returned HTTP {status}"
                    + (f" with title '{details['title']}'" if details.get("title") else "")
                    + "."
                ),
                recommendation=(
                    f"Restrict {admin} to trusted networks or place it behind a VPN/SSO proxy. "
                    "Confirm no default administrative account remains enabled."
                ),
                confidence=Confidence.PROBABLE,
                port=port,
                protocol=Protocol.TCP,
            )
        )

    return findings


async def run_checks(
    host: str, port: int, protocol: str, service: ServiceInfo
) -> list[FindingDraft]:
    findings = check_exposed_service(port, protocol, service)

    details = service.details or {}
    if details.get("scheme") in ("http", "https"):
        findings.extend(check_http(port, details))

    tls = details.get("tls")
    if isinstance(tls, dict):
        findings.extend(check_tls(port, tls))

    if service.name == "ftp" or port in (21, 990):
        anonymous = await check_anonymous_ftp(host, port)
        if anonymous is not None:
            findings.append(anonymous)

    return findings
