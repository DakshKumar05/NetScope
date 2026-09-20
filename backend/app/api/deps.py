from __future__ import annotations

from collections.abc import Iterator

from fastapi import Depends
from sqlalchemy.orm import Session

from app.database.session import SessionLocal
from app.services.scan_manager import ScanManager, get_manager


def get_session() -> Iterator[Session]:
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


def manager_dep() -> ScanManager:
    return get_manager()


SessionDep = Depends(get_session)
ManagerDep = Depends(manager_dep)
