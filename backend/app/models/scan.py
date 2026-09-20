from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING

from sqlalchemy import DateTime, Index, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import ScanStatus
from app.database.session import Base

if TYPE_CHECKING:
    from app.models.finding import Finding
    from app.models.host import Host


def utcnow() -> datetime:
    return datetime.now(UTC)


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    scan_type: Mapped[str] = mapped_column(String(32), default="quick", nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), default=ScanStatus.QUEUED, nullable=False, index=True
    )
    engine: Mapped[str] = mapped_column(String(32), default="socket", nullable=False)

    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    ports_spec: Mapped[str | None] = mapped_column(String(512), nullable=True)
    udp_enabled: Mapped[bool] = mapped_column(default=False, nullable=False)
    timeout: Mapped[float] = mapped_column(default=1.0, nullable=False)
    concurrency: Mapped[int] = mapped_column(Integer, default=100, nullable=False)

    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_score: Mapped[float] = mapped_column(default=0.0, nullable=False)

    hosts: Mapped[list["Host"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", lazy="selectin"
    )
    findings: Mapped[list["Finding"]] = relationship(
        back_populates="scan", cascade="all, delete-orphan", lazy="selectin"
    )

    __table_args__ = (Index("ix_scans_started_at", "started_at"),)

    @property
    def duration_seconds(self) -> float | None:
        if self.completed_at is None:
            return None
        return (self.completed_at - self.started_at).total_seconds()
