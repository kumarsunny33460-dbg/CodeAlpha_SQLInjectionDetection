"""Error handling and the shared JSON response envelope.

Every API response follows the same shape so that clients never have to guess
where the payload lives::

    {
        "success": true,
        "data": {...}
    }

    {
        "success": false,
        "type": "danger",
        "message": "...",
        "request_id": "..."
    }
"""

from __future__ import annotations

from typing import Any

from flask import jsonify
from werkzeug.exceptions import HTTPException

from .logging_config import get_logger, request_id_var

logger = get_logger("errors")


def envelope(success: bool, data=None, message: str = "", type_: str = "", **extra):
    """Build a JSON response using the shared envelope."""
    payload: dict[str, Any] = {"success": success}

    if data is not None:
        payload["data"] = data

    if message:
        payload["message"] = message

    if type_:
        payload["type"] = type_

    payload["request_id"] = request_id_var.get()

    payload.update(extra)

    return jsonify(payload)


def success(data=None, message: str = "", type_: str = "", status: int = 200, **extra):
    response = envelope(True, data=data, message=message, type_=type_, **extra)
    response.status_code = status
    return response


def failure(message: str, type_: str = "danger", status: int = 400, **extra):
    response = envelope(False, message=message, type_=type_, **extra)
    response.status_code = status
    return response


def register_error_handlers(app) -> None:
    """Attach the JSON error handlers to ``app``."""

    @app.errorhandler(400)
    def handle_bad_request(error):  # noqa: ANN001 - Flask passes the exception
        return failure("The request could not be understood.", "warning", 400)

    @app.errorhandler(404)
    def handle_not_found(error):  # noqa: ANN001
        return failure("Page not found.", "warning", 404)

    @app.errorhandler(405)
    def handle_method_not_allowed(error):  # noqa: ANN001
        return failure("This method is not allowed for the endpoint.", "warning", 405)

    @app.errorhandler(413)
    def handle_too_large(error):  # noqa: ANN001
        return failure("The submitted payload is too large.", "warning", 413)

    @app.errorhandler(429)
    def handle_rate_limited(error):  # noqa: ANN001
        response = failure(
            "Too many requests. Please slow down and try again.",
            "warning",
            429,
        )
        description = getattr(error, "description", "")
        if description:
            response = failure(description, "warning", 429)
        return response

    @app.errorhandler(500)
    def handle_internal_error(error):  # noqa: ANN001
        logger.exception("Unhandled server error")
        return failure("An internal server error occurred.", "danger", 500)

    @app.errorhandler(Exception)
    def handle_unexpected_error(error):  # noqa: ANN001
        if isinstance(error, HTTPException):
            return error
        logger.exception("Unhandled exception")
        return failure("An internal server error occurred.", "danger", 500)

    @app.after_request
    def attach_request_id(response):  # noqa: ANN001
        response.headers.setdefault("X-Request-ID", request_id_var.get())
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response


__all__ = ["envelope", "failure", "register_error_handlers", "success"]
