from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import HostStatus
from app.database.session import Base

if TYPE_CHECKING:
    from app.models.finding import Finding
    from app.models.port import Port
    from app.models.scan import Scan


class Host(Base):
    __tablename__ = "hosts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[int] = mapped_column(
        ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True
    )
    ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    hostname: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(16), default=HostStatus.UNKNOWN, nullable=False)
    risk_score: Mapped[float] = mapped_column(default=0.0, nullable=False)

    scan: Mapped["Scan"] = relationship(back_populates="hosts")
    ports: Mapped[list["Port"]] = relationship(
        back_populates="host", cascade="all, delete-orphan", lazy="selectin"
    )
    findings: Mapped[list["Finding"]] = relationship(back_populates="host", lazy="selectin")

    __table_args__ = (Index("ix_hosts_scan_ip", "scan_id", "ip"),)

    @property
    def open_ports(self) -> list["Port"]:
        from app.core.enums import PortState

        return [p for p in self.ports if p.state in (PortState.OPEN, PortState.OPEN_FILTERED)]
