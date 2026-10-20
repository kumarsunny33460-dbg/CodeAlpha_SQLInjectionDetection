"""Web interface routes."""

from __future__ import annotations

from flask import Blueprint, current_app, render_template

from ..logging_config import get_logger

logger = get_logger("api.web")

bp = Blueprint("web", __name__)


@bp.get("/")
def home():
    """Render the single page application."""
    return render_template(
        "index.html",
        app_version=current_app.config.get("APP_VERSION", ""),
        app_name=current_app.config.get("APP_NAME", "SQLShield"),
    )


__all__ = ["bp"]
