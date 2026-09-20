"""Banner-reading detectors: SSH, FTP, SMTP and a generic fallback.

All of these read what the service volunteers on connect. None of them
authenticate, guess credentials or send protocol commands beyond the
greeting exchange the protocol itself expects.
"""

from __future__ import annotations

import re

from app.config import settings
from app.core.enums import Confidence
from app.services.fingerprinting.base import ServiceDetector, ServiceInfo, read_banner

_SSH_RE = re.compile(r"^SSH-(?P<proto>[\d.]+)-(?P<software>[^\s\r\n]+)")
_OPENSSH_RE = re.compile(r"OpenSSH[_-](?P<version>[\w.]+)", re.I)
_VERSION_RE = re.compile(r"(?P<product>[A-Za-z][\w+.-]{1,40}?)[ /_-]v?(?P<version>\d+(\.\d+){1,3})")


def _split_product_version(text: str) -> tuple[str | None, str | None]:
    match = _VERSION_RE.search(text)
    if not match:
        return None, None
    return match.group("product"), match.group("version")


class SSHDetector(ServiceDetector):
    name = "ssh"
    ports = (22, 2222)

    def handles(self, port: int, hint: str | None) -> bool:
        return port in self.ports or hint == "ssh"

    async def detect(self, host: str, port: int) -> ServiceInfo | None:
        # SSH servers send their identification string unprompted.
        banner = await read_banner(host, port, timeout=settings.default_timeout + 1.5)
        if not banner:
            return None
        first = banner.splitlines()[0].strip()
        match = _SSH_RE.match(first)
        if not match:
            return None

        software = match.group("software")
        product, version = None, None
        openssh = _OPENSSH_RE.search(software)
        if openssh:
            product, version = "OpenSSH", openssh.group("version")
        else:
            product, version = _split_product_version(software)
            if product is None:
                product = software

        return ServiceInfo(
            name="ssh",
            product=product,
            version=version,
            banner=first,
            confidence=Confidence.CONFIRMED if version else Confidence.PROBABLE,
            details={"protocol_version": match.group("proto"), "software": software},
        )


class FTPDetector(ServiceDetector):
    name = "ftp"
    ports = (21, 990)

    def handles(self, port: int, hint: str | None) -> bool:
        return port in self.ports or hint == "ftp"

    async def detect(self, host: str, port: int) -> ServiceInfo | None:
        banner = await read_banner(host, port, timeout=settings.default_timeout + 1.5)
        if not banner or not banner.lstrip().startswith("220"):
            return None
        first = banner.splitlines()[0].strip()
        product, version = _split_product_version(first)
        lowered = first.lower()
        if product is None:
            for known in ("vsftpd", "proftpd", "pure-ftpd", "filezilla", "microsoft ftp"):
                if known in lowered:
                    product = known
                    break
        return ServiceInfo(
            name="ftp",
            product=product,
            version=version,
            banner=first,
            confidence=Confidence.PROBABLE if product else Confidence.POSSIBLE,
            details={"greeting": first},
        )


class SMTPDetector(ServiceDetector):
    name = "smtp"
    ports = (25, 465, 587, 2525)

    def handles(self, port: int, hint: str | None) -> bool:
        return port in self.ports or hint in ("smtp", "smtps")

    async def detect(self, host: str, port: int) -> ServiceInfo | None:
        banner = await read_banner(host, port, timeout=settings.default_timeout + 1.5)
        if not banner or not banner.lstrip().startswith("220"):
            return None
        first = banner.splitlines()[0].strip()
        product, version = _split_product_version(first)
        lowered = first.lower()
        if product is None:
            for known in ("postfix", "exim", "sendmail", "microsoft esmtp", "opensmtpd"):
                if known in lowered:
                    product = known
                    break
        return ServiceInfo(
            name="smtp",
            product=product,
            version=version,
            banner=first,
            confidence=Confidence.PROBABLE if product else Confidence.POSSIBLE,
            details={"greeting": first},
        )


class MySQLDetector(ServiceDetector):
    """MySQL/MariaDB announce their version in the initial handshake packet.

    Wire format: 3-byte payload length, 1-byte sequence id, 1-byte protocol
    version, then a NUL-terminated version string. Reading it is passive - no
    login packet is ever sent.
    """

    name = "mysql"
    ports = (3306, 33060)

    def handles(self, port: int, hint: str | None) -> bool:
        return port in self.ports or hint == "mysql"

    async def detect(self, host: str, port: int) -> ServiceInfo | None:
        raw = await read_banner(host, port, timeout=settings.default_timeout + 1.5)
        if not raw or len(raw) < 6:
            return None
        # read_banner decodes leniently, which is fine: the version string is ASCII.
        body = raw[4:] if raw[4:5] not in ("", "\n") else raw[5:]
        version_text = body.split("\x00", 1)[0].strip()
        match = re.match(r"(\d+\.\d+\.\d+[\w.-]*)", version_text)
        if not match:
            return None
        full = match.group(1)
        product = "MariaDB" if "mariadb" in full.lower() else "MySQL"
        return ServiceInfo(
            name="mysql",
            product=product,
            version=full,
            banner=f"{product} {full}",
            confidence=Confidence.CONFIRMED,
            details={"handshake_version": full},
        )


class GenericBannerDetector(ServiceDetector):
    """Last resort: read whatever the port volunteers, claim little about it."""

    name = "generic"

    def handles(self, port: int, hint: str | None) -> bool:
        return True

    async def detect(self, host: str, port: int) -> ServiceInfo | None:
        banner = await read_banner(host, port, timeout=settings.default_timeout + 0.5)
        if not banner:
            # Some services stay silent until spoken to; one newline is enough
            # to elicit a greeting from line-oriented protocols.
            banner = await read_banner(
                host, port, timeout=settings.default_timeout + 0.5, send=b"\r\n"
            )
        if not banner:
            return None
        first = banner.splitlines()[0].strip()[:300]
        product, version = _split_product_version(first)
        return ServiceInfo(
            name="unknown",
            product=product,
            version=version,
            banner=first,
            confidence=Confidence.POSSIBLE,
            details={"raw_banner": first},
        )
