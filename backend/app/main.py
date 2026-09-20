from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api import routes_dashboard, routes_findings, routes_hosts, routes_scans
from app.config import settings
from app.core.targets import TargetValidationError
from app.database.session import init_db
from app.services.scanner import nmap_available
from app.services.scan_manager import get_manager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s | %(message)s",
)
logger = logging.getLogger("nes")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    logger.info(
        "Network Exposure Scanner ready (nmap engine %s, public targets %s)",
        "available" if nmap_available() else "unavailable",
        "allowed" if settings.allow_public_targets else "blocked",
    )
    yield
    await get_manager().shutdown()


app = FastAPI(
    title="Network Exposure Scanner",
    version="1.0.0",
    description=(
        "An authorised, defensive network exposure scanner. Probes hosts you own "
        "or are explicitly permitted to test, fingerprints the services it finds, "
        "and reports exposure with the evidence behind every conclusion."
    ),
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.origins,
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


def _error(status_code: int, message: str, detail: object = None) -> JSONResponse:
    body: dict[str, object] = {"error": {"message": message, "status": status_code}}
    if detail is not None:
        body["error"]["detail"] = detail
    return JSONResponse(status_code=status_code, content=body)


@app.exception_handler(TargetValidationError)
async def _target_error(_request: Request, exc: TargetValidationError) -> JSONResponse:
    return _error(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc))


@app.exception_handler(StarletteHTTPException)
async def _http_error(_request: Request, exc: StarletteHTTPException) -> JSONResponse:
    """Route HTTPExceptions through the same envelope as everything else.

    Without this, a 404 returns FastAPI's {"detail": ...} while a validation
    failure returns {"error": {...}} - two shapes for the same client to parse.
    """
    return _error(exc.status_code, str(exc.detail))


@app.exception_handler(RequestValidationError)
async def _validation_error(_request: Request, exc: RequestValidationError) -> JSONResponse:
    return _error(
        status.HTTP_422_UNPROCESSABLE_ENTITY,
        "Request validation failed.",
        detail=[
            {"field": ".".join(str(p) for p in e.get("loc", [])), "message": e.get("msg")}
            for e in exc.errors()
        ],
    )


@app.exception_handler(Exception)
async def _unhandled(_request: Request, exc: Exception) -> JSONResponse:
    logger.exception("unhandled error")
    return _error(
        status.HTTP_500_INTERNAL_SERVER_ERROR,
        "An unexpected error occurred. Check the server log for details.",
    )


app.include_router(routes_scans.router)
app.include_router(routes_hosts.router)
app.include_router(routes_findings.router)
app.include_router(routes_dashboard.router)


@app.get("/api/health", tags=["meta"])
def health() -> dict:
    return {
        "status": "ok",
        "engines": {"socket": True, "nmap": nmap_available()},
        "public_targets_allowed": settings.allow_public_targets,
        "active_scans": get_manager().active_ids(),
    }
