from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sqlalchemy import JSON, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.enums import Confidence
from app.database.session import Base

if TYPE_CHECKING:
    from app.models.port import Port


class Service(Base):
    __tablename__ = "services"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    port_id: Mapped[int] = mapped_column(
        ForeignKey("ports.id", ondelete="CASCADE"), nullable=False, index=True, unique=True
    )
    name: Mapped[str] = mapped_column(String(64), default="unknown", nullable=False)
    product: Mapped[str | None] = mapped_column(String(128), nullable=True)
    version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    banner: Mapped[str | None] = mapped_column(Text, nullable=True)
    confidence: Mapped[str] = mapped_column(
        String(16), default=Confidence.POSSIBLE, nullable=False
    )

    # Protocol-specific metadata (HTTP headers, TLS certificate fields, ...).
    details: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict, nullable=False)

    port: Mapped["Port"] = relationship(back_populates="service")
