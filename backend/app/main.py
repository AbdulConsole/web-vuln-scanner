"""
Application entrypoint.

Run locally with:
    uvicorn app.main:app --reload

The app factory pattern (create_app) is used so tests can construct fresh
app instances with overridden settings/dependencies without import-order
side effects.
"""
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import findings, health, reports, scans, targets
from app.core.config import get_settings
from app.core.exceptions import register_exception_handlers
from app.core.logging import configure_logging, get_logger

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    settings = get_settings()
    logger.info(
        "Starting application",
        extra={"context": {"environment": settings.ENVIRONMENT}},
    )
    from app.database.database import init_models
    await init_models()
    yield
    logger.info("Shutting down application")


def create_app() -> FastAPI:
    settings = get_settings()

    app = FastAPI(
        title=settings.APP_NAME,
        version=settings.APP_VERSION,
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    register_exception_handlers(app)

    app.include_router(health.router, prefix="/api")
    app.include_router(targets.router, prefix="/api")
    app.include_router(scans.router, prefix="/api")
    app.include_router(findings.router, prefix="/api")
    app.include_router(reports.router, prefix="/api")

    return app


app = create_app()
