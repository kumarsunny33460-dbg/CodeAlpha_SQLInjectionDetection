"""Security event endpoints.

These expose the recorded security events for the monitoring interface. Event
payloads are never returned: only metadata such as the category, the severity
and the source is exposed.
"""

from __future__ import annotations

from flask import Blueprint, current_app, request

from ..errors import failure, success
from ..extensions import limiter
from ..logging_config import get_logger

logger = get_logger("api.events")

api_bp = Blueprint("api_events", __name__, url_prefix="/api/v1")


@api_bp.get("/security/events")
@limiter.limit(lambda: current_app.config.get("RATELIMIT_DASHBOARD", "60 per minute"))
def list_events():
    """Return the most recent security events."""
    try:
        limit = min(int(request.args.get("limit", 25)), 200)
    except (TypeError, ValueError):
        limit = 25

    limit = max(1, limit)

    try:
        events = current_app.extensions["event_repository"].recent(limit=limit)
    except Exception:  # noqa: BLE001
        logger.exception("Security events could not be loaded")
        return failure("Unable to load security events.", "danger", 500)

    return success(data={"events": events, "count": len(events)})


@api_bp.get("/security/timeline")
@limiter.limit(lambda: current_app.config.get("RATELIMIT_DASHBOARD", "60 per minute"))
def security_timeline():
    """Return the daily event counts used by the activity chart."""
    try:
        days = min(int(request.args.get("days", 7)), 90)
    except (TypeError, ValueError):
        days = 7

    try:
        timeline = current_app.extensions["event_repository"].timeline(days=days)
    except Exception:  # noqa: BLE001
        logger.exception("Security timeline could not be loaded")
        return failure("Unable to load the security timeline.", "danger", 500)

    return success(data={"timeline": timeline})


@api_bp.post("/security/detect")
@limiter.limit(lambda: current_app.config.get("RATELIMIT_REGISTRATION", "30 per minute"))
def detect():
    """Run the detection engine against a payload without storing anything.

    This endpoint powers the interactive threat scanner in the security
    centre and is intentionally read only.
    """
    from ..security.detector import analyse

    payload = request.get_json(silent=True)

    if not isinstance(payload, dict):
        return failure("A JSON request body is required.", "warning", 400)

    target = payload.get("value")
    field_name = str(payload.get("field", "value"))

    if not isinstance(target, str) or not target.strip():
        return failure("A 'value' string is required.", "warning", 400)

    threshold = current_app.config.get("SQLI_BLOCK_THRESHOLD", 40)
    result = analyse(target, field_name=field_name, threshold=threshold)

    return success(data=result.to_dict())


__all__ = ["api_bp"]
