"""Health check endpoints.

``/health/live`` answers whether the process is running. ``/health/ready``
additionally verifies the database connection and therefore reports a degraded
state instead of failing when MongoDB is temporarily unreachable.
"""

from __future__ import annotations

from datetime import UTC, datetime

from flask import Blueprint, current_app

from ..errors import success
from ..logging_config import get_logger

logger = get_logger("api.health")

api_bp = Blueprint("health", __name__, url_prefix="/health")
v1_bp = Blueprint("api_health", __name__, url_prefix="/api/v1")


def _liveness_payload() -> dict:
    return {
        "status": "alive",
        "app": current_app.config.get("APP_NAME", "SQLShield"),
        "version": current_app.config.get("APP_VERSION", ""),
        "environment": current_app.config.get("ENV_NAME", "development"),
        "timestamp": datetime.now(UTC).isoformat(),
    }


def _readiness_payload() -> tuple[dict, bool]:
    mongo = current_app.extensions["mongo"]
    connected = mongo.ping()

    payload = {
        "status": "ready" if connected else "degraded",
        "database": {
            "connected": connected,
            "name": current_app.config.get("DATABASE_NAME", ""),
            "error": mongo.last_error if not connected else "",
        },
        "encryption": {
            "configured": bool(current_app.extensions["key_vault"].is_ready),
            "active_key_id": current_app.extensions["key_vault"].active_key_id,
        },
        "capability_verification": {
            "configured": bool(
                current_app.extensions["capability_verifier"].is_configured
            )
        },
        "timestamp": datetime.now(UTC).isoformat(),
    }

    return payload, connected


@api_bp.get("/live")
def live():
    """Liveness probe."""
    return success(data=_liveness_payload())


@api_bp.get("/ready")
def ready():
    """Readiness probe including the database connection."""
    payload, connected = _readiness_payload()
    response = success(data=payload)
    response.status_code = 200 if connected else 503
    return response


@v1_bp.get("/health")
def health():
    """Combined health payload."""
    payload, connected = _readiness_payload()
    payload["liveness"] = _liveness_payload()
    response = success(data=payload)
    response.status_code = 200 if connected else 503
    return response


__all__ = ["api_bp", "v1_bp"]
