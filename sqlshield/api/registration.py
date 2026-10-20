"""Registration endpoints.

``POST /api/v1/register`` is the current endpoint. ``POST /register`` is kept
as a backwards compatible alias for the original v1 client.
"""

from __future__ import annotations

from flask import Blueprint, current_app, request

from ..errors import failure, success
from ..extensions import limiter
from ..logging_config import get_logger
from .helpers import client_context

logger = get_logger("api.registration")

api_bp = Blueprint("api_registration", __name__, url_prefix="/api/v1")
legacy_bp = Blueprint("legacy_registration", __name__)


def _register():
    service = current_app.extensions["registration_service"]

    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return failure(
            "A JSON request body is required.",
            "warning",
            400,
        )

    outcome = service.register(payload, context=client_context())

    if outcome.success:
        return success(
            data=outcome.details,
            message=outcome.message,
            type_=outcome.type,
            status=outcome.status,
        )

    if outcome.detection:
        return failure(
            outcome.message,
            outcome.type,
            outcome.status,
            detection=outcome.detection,
        )

    extra = {"details": outcome.details} if outcome.details else {}

    return failure(
        outcome.message,
        outcome.type,
        outcome.status,
        **extra,
    )


@api_bp.post("/register")
@limiter.limit(lambda: current_app.config.get("RATELIMIT_REGISTRATION", "10 per minute"))
def register_v1():
    """Register a new secure record."""
    return _register()


@legacy_bp.post("/register")
@limiter.limit(lambda: current_app.config.get("RATELIMIT_REGISTRATION", "10 per minute"))
def register_legacy():
    """Backwards compatible alias of the v1 registration endpoint."""
    return _register()


__all__ = ["api_bp", "legacy_bp"]
