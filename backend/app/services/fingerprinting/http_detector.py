"""HTTP/HTTPS identification.

One GET to the document root, redirects followed, headers and <title> read.
No directory brute-forcing, no authentication attempts, no payloads.
"""

from __future__ import annotations

import re

import httpx

from app.config import settings
from app.core.enums import Confidence
from app.services.fingerprinting.base import ServiceDetector, ServiceInfo

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_SERVER_VERSION_RE = re.compile(r"^(?P<product>[^/\s]+)(?:/(?P<version>[\w.\-]+))?")

HTTP_PORTS = (80, 3000, 5000, 8000, 8008, 8080, 8081, 8088, 8888, 9000, 9090)
HTTPS_PORTS = (443, 8443, 9443, 6443)

# Fingerprints for administrative interfaces. Presence only - never a login attempt.
ADMIN_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("jenkins", "Jenkins"),
    ("grafana", "Grafana"),
    ("kibana", "Kibana"),
    ("phpmyadmin", "phpMyAdmin"),
    ("webmin", "Webmin"),
    ("tomcat", "Apache Tomcat"),
    ("portainer", "Portainer"),
    ("rabbitmq", "RabbitMQ Management"),
    ("pgadmin", "pgAdmin"),
    ("adminer", "Adminer"),
    ("gitlab", "GitLab"),
    ("nexus repository", "Sonatype Nexus"),
    ("jupyter", "Jupyter"),
)

SECURITY_HEADERS: tuple[str, ...] = (
    "strict-transport-security",
    "content-security-policy",
    "x-content-type-options",
    "x-frame-options",
    "referrer-policy",
)


def _parse_server_header(value: str) -> tuple[str | None, str | None]:
    match = _SERVER_VERSION_RE.match(value.strip())
    if not match:
        return None, None
    return match.group("product"), match.group("version")


def _detect_admin_interface(title: str, body: str, headers: dict[str, str]) -> str | None:
    haystack = " ".join([title.lower(), body[:4000].lower(), " ".join(headers.values()).lower()])
    for needle, label in ADMIN_SIGNATURES:
        if needle in haystack:
            return label
    return None


class HTTPDetector(ServiceDetector):
    name = "http"
    ports = HTTP_PORTS

    scheme = "http"

    def handles(self, port: int, hint: str | None) -> bool:
        return port in self.ports or hint == "http"

    async def detect(self, host: str, port: int) -> ServiceInfo | None:
        return await self.probe(host, port, self.scheme)

    async def probe(self, host: str, port: int, scheme: str) -> ServiceInfo | None:
        """One GET against the document root. Safe to call on any open port."""
        url = f"{scheme}://{host}:{port}/"
        redirects: list[str] = []
        try:
            async with httpx.AsyncClient(
                timeout=settings.http_timeout,
                verify=False,  # noqa: S501 - cert problems are findings, not fatal errors
                follow_redirects=True,
                max_redirects=4,
                headers={"User-Agent": "NetworkExposureScanner/1.0 (authorised-scan)"},
            ) as client:
                response = await client.get(url)
                redirects = [str(r.url) for r in response.history]
        except (httpx.HTTPError, OSError):
            return None

        headers = {k.lower(): v for k, v in response.headers.items()}
        body = ""
        try:
            body = response.text
        except (UnicodeDecodeError, httpx.HTTPError):
            body = ""

        title_match = _TITLE_RE.search(body)
        title = re.sub(r"\s+", " ", title_match.group(1)).strip()[:200] if title_match else ""

        server_header = headers.get("server", "")
        product, version = _parse_server_header(server_header) if server_header else (None, None)
        powered_by = headers.get("x-powered-by")

        missing_headers = [h for h in SECURITY_HEADERS if h not in headers]
        admin_interface = _detect_admin_interface(title, body, headers)

        details = {
            "scheme": scheme,
            "url": str(response.url),
            "status_code": response.status_code,
            "server": server_header or None,
            "powered_by": powered_by,
            "title": title or None,
            "redirects": redirects,
            "missing_security_headers": missing_headers,
            "admin_interface": admin_interface,
            "content_type": headers.get("content-type"),
            "requires_auth": response.status_code in (401, 403),
        }

        confidence = Confidence.CONFIRMED if version else Confidence.PROBABLE
        return ServiceInfo(
            name=scheme,
            product=product,
            version=version,
            banner=f"HTTP {response.status_code} {server_header}".strip(),
            confidence=confidence if product else Confidence.POSSIBLE,
            details=details,
        )


class HTTPSDetector(HTTPDetector):
    name = "https"
    ports = HTTPS_PORTS
    scheme = "https"

    def handles(self, port: int, hint: str | None) -> bool:
        return port in self.ports or hint == "https"
