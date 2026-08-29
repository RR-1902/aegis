"""Read-only REST API for persisted AEGIS security events."""

from __future__ import annotations

from fastapi import FastAPI

from app.api.routes.events import router as events_router
from app.api.routes.health import router as health_router
from app.config.settings import settings


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    docs_url="/docs",
    redoc_url="/redoc",
)

app.include_router(health_router)
app.include_router(events_router)
