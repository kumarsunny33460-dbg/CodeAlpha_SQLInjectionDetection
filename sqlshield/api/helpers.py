"""Shared helpers for the HTTP layer."""

from __future__ import annotations

from flask import request

from ..logging_config import request_id_var


def client_context() -> dict[str, str]:
    """Collect the request metadata stored alongside security events."""
    forwarded = request.headers.get("X-Forwarded-For", "")

    if forwarded:
        ip_address = forwarded.split(",")[0].strip()
    else:
        ip_address = request.remote_addr or ""

    return {
        "ip_address": ip_address,
        "user_agent": (request.headers.get("User-Agent", "") or "")[:300],
        "request_id": request_id_var.get(),
        "path": request.path,
        "method": request.method,
    }


__all__ = ["client_context"]
