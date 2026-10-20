"""Dashboard endpoints.

``GET /api/v1/dashboard`` returns the aggregated security view. The legacy
``GET /api/dashboard`` alias is preserved for the v1 client.
"""

from __future__ import annotations

from flask import Blueprint, current_app

from ..db.repositories import EVENT_SQL_INJECTION, EVENT_UNAUTHORIZED_ACCESS
from ..errors import success
from ..extensions import limiter
from ..logging_config import get_logger

logger = get_logger("api.dashboard")

api_bp = Blueprint("api_dashboard", __name__, url_prefix="/api/v1")
legacy_bp = Blueprint("legacy_dashboard", __name__)


def _build_payload():
    users = current_app.extensions["user_repository"]
    events = current_app.extensions["event_repository"]
    mongo = current_app.extensions["mongo"]

    counts = events.counts_by_type()

    sql_attacks = counts.get(EVENT_SQL_INJECTION, 0)
    unauthorized = counts.get(EVENT_UNAUTHORIZED_ACCESS, 0)
    total_events = sum(counts.values())

    return {
        "statistics": {
            "total_users": users.count(),
            "sql_attacks": sql_attacks,
            "unauthorized_attempts": unauthorized,
            "security_events": total_events,
            "events_by_type": counts,
        },
        "recent_users": users.recent(limit=8),
        "recent_logs": events.recent(limit=8),
        "timeline": events.timeline(days=7),
        "attack_categories": events.top_attack_categories(limit=5),
        "system": {
            "database_connected": mongo.is_connected,
            "database_error": mongo.last_error,
            "app_version": current_app.config.get("APP_VERSION", ""),
        },
    }


def _dashboard():
    try:
        return success(data=_build_payload())
    except Exception as error:  # noqa: BLE001
        logger.exception("Dashboard data could not be loaded")
        from ..errors import failure

        return failure(
            "Unable to load dashboard data.",
            "danger",
            500,
            detail=str(error) if current_app.config.get("DEBUG") else "",
        )


@api_bp.get("/dashboard")
@limiter.limit(lambda: current_app.config.get("RATELIMIT_DASHBOARD", "60 per minute"))
def dashboard_v1():
    """Return the aggregated dashboard payload."""
    return _dashboard()


@legacy_bp.get("/api/dashboard")
@limiter.limit(lambda: current_app.config.get("RATELIMIT_DASHBOARD", "60 per minute"))
def dashboard_legacy():
    """Backwards compatible alias of the v1 dashboard endpoint."""
    return _dashboard()


__all__ = ["api_bp", "legacy_bp"]
