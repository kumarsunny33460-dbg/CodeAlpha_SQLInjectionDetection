"""HTTP layer for SQLShield."""

from __future__ import annotations

from .dashboard import api_bp as dashboard_api_bp
from .dashboard import legacy_bp as dashboard_legacy_bp
from .events import api_bp as events_api_bp
from .health import api_bp as health_bp
from .health import v1_bp as health_v1_bp
from .registration import api_bp as registration_api_bp
from .registration import legacy_bp as registration_legacy_bp
from .web import bp as web_bp

__all__ = [
    "dashboard_api_bp",
    "dashboard_legacy_bp",
    "events_api_bp",
    "health_bp",
    "health_v1_bp",
    "registration_api_bp",
    "registration_legacy_bp",
    "web_bp",
]
