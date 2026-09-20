from __future__ import annotations

import asyncio
import logging

from app.core.enums import Confidence
from app.services.fingerprinting.banner_detectors import (
    FTPDetector,
    GenericBannerDetector,
    MySQLDetector,
    SMTPDetector,
    SSHDetector,
)
from app.services.fingerprinting.base import ServiceDetector, ServiceInfo
from app.services.fingerprinting.http_detector import HTTPDetector, HTTPSDetector
from app.services.fingerprinting.tls_detector import TLSDetector

logger = logging.getLogger(__name__)

# Order matters: the first detector that both volunteers for the port and
# returns a result wins. GenericBannerDetector is last because it claims all ports.
DEFAULT_DETECTORS: tuple[ServiceDetector, ...] = (
    HTTPSDetector(),
    HTTPDetector(),
    SSHDetector(),
    FTPDetector(),
    SMTPDetector(),
    MySQLDetector(),
    GenericBannerDetector(),
)

_TLS_DETECTOR = TLSDetector()
_HTTP_FALLBACK = HTTPDetector()
_HTTPS_FALLBACK = HTTPSDetector()


class FingerprintRegistry:
    """Runs the detector chain against one open port."""

    def __init__(self, detectors: tuple[ServiceDetector, ...] = DEFAULT_DETECTORS) -> None:
        self.detectors = detectors

    def register(self, detector: ServiceDetector) -> None:
        # Insert ahead of the generic fallback so new detectors get a real chance.
        self.detectors = (*self.detectors[:-1], detector, self.detectors[-1])

    @staticmethod
    async def _try_web(host: str, port: int, existing: ServiceInfo | None) -> ServiceInfo | None:
        """Last-resort HTTP(S) probe for ports no detector claimed."""
        banner = (existing.banner or "") if existing else ""
        # A plaintext HTTP banner means TLS would only waste a handshake.
        order = (
            (_HTTP_FALLBACK, "http")
            if "HTTP/" in banner
            else (_HTTPS_FALLBACK, "https")
        )
        attempts = [order, (_HTTP_FALLBACK, "http")] if order[1] == "https" else [order]
        for detector, scheme in attempts:
            try:
                result = await detector.probe(host, port, scheme)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                continue
            if result is not None:
                return result
        return None

    async def identify(self, host: str, port: int, hint: str | None = None) -> ServiceInfo:
        info: ServiceInfo | None = None
        for detector in self.detectors:
            if not detector.handles(port, hint):
                continue
            try:
                info = await detector.detect(host, port)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001 - one bad detector must not sink a scan
                logger.debug("detector %s failed on %s:%s", detector.name, host, port, exc_info=True)
                continue
            if info is not None:
                break

        # Web services on non-standard ports are the common case, not the
        # exception, so an unidentified port gets one HTTP(S) attempt before
        # we give up on it.
        if info is None or not info.identified:
            fallback = await self._try_web(host, port, info)
            if fallback is not None:
                info = fallback

        if info is None:
            info = ServiceInfo(name=hint or "unknown", confidence=Confidence.POSSIBLE)
        elif info.name == "unknown" and hint:
            info.name = hint

        # TLS inspection runs alongside whatever the port turned out to be, so
        # an HTTPS service carries both its HTTP identity and its certificate.
        if _TLS_DETECTOR.handles(port, info.name if info.name != "unknown" else hint):
            try:
                tls_info = await _TLS_DETECTOR.detect(host, port)
            except asyncio.CancelledError:
                raise
            except Exception:  # noqa: BLE001
                tls_info = None
            if tls_info is not None:
                info.details["tls"] = tls_info.details
                if not info.identified:
                    info.name = "tls"

        return info


registry = FingerprintRegistry()
