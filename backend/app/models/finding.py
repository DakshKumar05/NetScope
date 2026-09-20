from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

from sqlalchemy import JSON, DateTime, ForeignKey, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import Confidence, Severity
from app.database.session import Base
from app.models.scan import utcnow

if TYPE_CHECKING:
    from app.models.host import Host
    from app.models.scan import Scan


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    host_id: Mapped[int | None] = mapped_column(
        ForeignKey("hosts.id", ondelete="CASCADE"), nullable=True, index=True
    )
    port_id: Mapped[int | None] = mapped_column(
        ForeignKey("ports.id", ondelete="CASCADE"), nullable=True, index=True
    )

    type: Mapped[str] = mapped_column(String(48), nullable=False, index=True)
    severity: Mapped[str] = mapped_column(
        String(16), default=Severity.INFO, nullable=False, index=True
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)

    # Why this severity was assigned — never hidden from the user.
    reason: Mapped[str] = mapped_column(Text, default="", nullable=False)
    evidence: Mapped[str] = mapped_column(Text, default="", nullable=False)
    recommendation: Mapped[str] = mapped_column(Text, default="", nullable=False)

    cve_id: Mapped[str | None] = mapped_column(String(32), nullable=True, index=True)
    cvss: Mapped[float | None] = mapped_column(nullable=True)
    confidence: Mapped[str] = mapped_column(
        String(16), default=Confidence.POSSIBLE, nullable=False
    )
    references: Mapped[list[str]] = mapped_column(JSON, default=list, nullable=False)
    extra: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)

    scan: Mapped["Scan"] = relationship(back_populates="findings")
    host: Mapped["Host | None"] = relationship(back_populates="findings")

    __table_args__ = (
        Index("ix_findings_scan_severity", "scan_id", "severity"),
        Index("ix_findings_type_severity", "type", "severity"),
    )
