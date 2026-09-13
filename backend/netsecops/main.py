"""FastAPI application factory."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from netsecops import __version__
from netsecops.api.middleware import (
    CorrelationIdMiddleware,
    RateLimitMiddleware,
    RequestLoggingMiddleware,
    SecurityHeadersMiddleware,
)
from netsecops.api.router import api_v1_router
from netsecops.api.v1 import health
from netsecops.core.config import Settings, get_settings
from netsecops.core.errors import register_exception_handlers
from netsecops.core.logging import configure_logging, get_logger
from netsecops.db.session import dispose_engine

DESCRIPTION = """
Read-only configuration and vulnerability assessment for network and security
infrastructure: Cisco, Palo Alto Networks, Fortinet and Check Point.

**NetSecOps never modifies a target device.** Every adapter declares an explicit
allow-list of read commands and API calls; anything outside it is rejected before
transmission, and every command issued is recorded in the audit log (SRS §8).
"""


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings: Settings = app.state.settings
    log = get_logger(__name__)
    log.info(
        "app.startup",
        version=__version__,
        environment=settings.env.value,
        metrics_enabled=settings.metrics_enabled,
    )
    yield
    log.info("app.shutdown")
    await dispose_engine()


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging()

    app = FastAPI(
        title=settings.app_name,
        description=DESCRIPTION,
        version=__version__,
        lifespan=lifespan,
        openapi_url="/api/v1/openapi.json",  # FR-INT-04
        docs_url="/api/v1/docs" if not settings.is_production else None,
        redoc_url="/api/v1/redoc" if not settings.is_production else None,
        # Problem-details are produced by our own handlers (SRS §4.2).
        responses={
            400: {"description": "Bad request"},
            401: {"description": "Not authenticated"},
            403: {"description": "Permission denied"},
            422: {"description": "Validation failed"},
        },
    )
    app.state.settings = settings

    # Middleware runs bottom-up: correlation id is outermost so every log line and
    # error response carries it.
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(SecurityHeadersMiddleware, settings=settings)
    app.add_middleware(CorrelationIdMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,  # required for the HttpOnly auth cookies
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
        allow_headers=["Authorization", "Content-Type", "X-CSRF-Token", "X-Correlation-ID"],
        expose_headers=["X-Correlation-ID", "X-Response-Time-ms"],
        max_age=600,
    )

    register_exception_handlers(app)

    app.include_router(health.router)  # root-level probes
    app.include_router(api_v1_router)

    return app


app = create_app()
