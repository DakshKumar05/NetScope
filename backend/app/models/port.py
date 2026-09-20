from __future__ import annotations

from typing import TYPE_CHECKING

from sqlalchemy import ForeignKey, Index, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import PortState, Protocol
from app.database.session import Base

if TYPE_CHECKING:
    from app.models.host import Host
    from app.models.service import Service


class Port(Base):
    __tablename__ = "ports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    host_id: Mapped[int] = mapped_column(
        ForeignKey("hosts.id", ondelete="CASCADE"), nullable=False, index=True
    )
    port: Mapped[int] = mapped_column(Integer, nullable=False)
    protocol: Mapped[str] = mapped_column(String(8), default=Protocol.TCP, nullable=False)
    state: Mapped[str] = mapped_column(String(16), default=PortState.UNKNOWN, nullable=False)
    service_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    latency_ms: Mapped[float | None] = mapped_column(nullable=True)

    host: Mapped["Host"] = relationship(back_populates="ports")
    service: Mapped["Service | None"] = relationship(
        back_populates="port", cascade="all, delete-orphan", uselist=False, lazy="selectin"
    )

    __table_args__ = (Index("ix_ports_host_port_proto", "host_id", "port", "protocol"),)
