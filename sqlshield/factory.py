"""Application factory.

``create_app`` builds a fully configured Flask application from an
environment driven configuration class. The factory is the only place where
the components are wired together, which keeps the modules importable and
testable in isolation.
"""

from __future__ import annotations

import hashlib
import os
import time
from pathlib import Path
from typing import Any

from flask import Flask, g, request
from werkzeug.middleware.proxy_fix import ProxyFix

from .api import (
    dashboard_api_bp,
    dashboard_legacy_bp,
    events_api_bp,
    health_bp,
    health_v1_bp,
    registration_api_bp,
    registration_legacy_bp,
    web_bp,
)
from .config import BaseConfig, resolve_config
from .db.mongo import DatabaseUnavailable, UnavailableCollection, mongo
from .db.repositories import EventRepository, UserRepository
from .errors import register_error_handlers
from .extensions import init_extensions
from .logging_config import (
    configure_logging,
    get_logger,
    new_request_id,
    request_id_var,
    user_agent_var,
)
from .security.capability import CapabilityVerifier
from .security.crypto import KeyVault, decode_key
from .services.registration import RegistrationService

logger = get_logger("factory")


def _apply_config(app: Flask, config_class) -> None:
    app.config.from_object(config_class)
    app.config["ENV_NAME"] = os.getenv("FLASK_ENV", "development").lower()


def _register_request_hooks(app: Flask) -> None:
    @app.before_request
    def _assign_request_id() -> None:
        request_id = request.headers.get("X-Request-ID") or new_request_id()
        request_id_var.set(request_id[:64])
        user_agent_var.set((request.headers.get("User-Agent", "") or "")[:300])
        g.request_id = request_id
        g.request_started_at = time.perf_counter()

    @app.after_request
    def _log_request(response):
        if not app.config.get("LOG_REQUESTS", True):
            return response

        started_at = getattr(g, "request_started_at", None)
        duration_ms = (
            round((time.perf_counter() - started_at) * 1000, 2)
            if started_at is not None
            else None
        )

        logger.info(
            "request",
            extra={
                "context": {
                    "method": request.method,
                    "path": request.path,
                    "status": response.status_code,
                    "duration_ms": duration_ms,
                    "ip": request.remote_addr,
                }
            },
        )
        return response


def _fingerprint_key(app: Flask, vault: KeyVault) -> bytes:
    """Derive the key used for the email lookup fingerprint.

    A dedicated ``FINGERPRINT_KEY`` keeps the fingerprints stable across an
    encryption key rotation. Without it the active AES key is used, which
    means rotating the key also changes every fingerprint.
    """
    configured = app.config.get("FINGERPRINT_KEY") or ""

    if configured:
        return decode_key(configured)

    if vault.is_ready:
        active = vault.keys[vault.active_key_id]
        return hashlib.sha256(b"sqlshield-fingerprint|" + active).digest()

    return b"sqlshield-fingerprint"


def _build_repositories(app: Flask) -> tuple[UserRepository, EventRepository]:
    vault: KeyVault = app.extensions["key_vault"]

    fingerprint_key = _fingerprint_key(app, vault)

    try:
        users = UserRepository(mongo.users, fingerprint_key=fingerprint_key)
        events = EventRepository(mongo.events)
    except DatabaseUnavailable as error:
        logger.error(
            "Repositories are unavailable",
            extra={"context": {"error": str(error)}},
        )
        placeholder = UnavailableCollection(str(error))
        users = UserRepository(placeholder, fingerprint_key=fingerprint_key)
        events = EventRepository(placeholder)

    app.extensions["user_repository"] = users
    app.extensions["event_repository"] = events

    return users, events


def create_app(
    config_name: str | None = None,
    config_overrides: dict[str, Any] | None = None,
) -> Flask:
    """Create and configure the Flask application."""
    config_class = resolve_config(config_name)

    project_root = Path(__file__).resolve().parent.parent

    app = Flask(
        __name__,
        template_folder=str(project_root / "templates"),
        static_folder=str(project_root / "static"),
        static_url_path="/static",
    )
    _apply_config(app, config_class)

    if config_overrides:
        app.config.update(config_overrides)

    configure_logging(app)

    # Proxy awareness for deployments behind a load balancer.
    proxy_count = int(app.config.get("TRUSTED_PROXY_COUNT", 1) or 0)
    if proxy_count > 0:
        app.wsgi_app = ProxyFix(  # type: ignore[method-assign]
            app.wsgi_app,
            x_for=proxy_count,
            x_proto=proxy_count,
            x_host=proxy_count,
        )

    init_extensions(app)

    # --- security material -----------------------------------------
    vault = KeyVault.from_config(app.config)
    app.extensions["key_vault"] = vault

    verifier = CapabilityVerifier.from_config(app.config)
    app.extensions["capability_verifier"] = verifier

    if not vault.is_ready:
        logger.warning(
            "No AES key configured: encrypted storage is disabled until "
            "AES_KEYS is provided."
        )

    if not verifier.is_configured:
        logger.warning("No capability code configured: registrations will be denied.")

    # --- persistence ------------------------------------------------
    mongo.init_app(app)
    users, events = _build_repositories(app)

    app.extensions["registration_service"] = RegistrationService(
        user_repository=users,
        event_repository=events,
        key_vault=vault,
        capability_verifier=verifier,
        config=app.config,
    )

    # --- routing ----------------------------------------------------
    app.register_blueprint(web_bp)
    app.register_blueprint(registration_api_bp)
    app.register_blueprint(registration_legacy_bp)
    app.register_blueprint(dashboard_api_bp)
    app.register_blueprint(dashboard_legacy_bp)
    app.register_blueprint(events_api_bp)
    app.register_blueprint(health_bp)
    app.register_blueprint(health_v1_bp)

    register_error_handlers(app)
    _register_request_hooks(app)

    logger.info(
        "Application ready",
        extra={
            "context": {
                "environment": app.config.get("ENV_NAME"),
                "version": app.config.get("APP_VERSION"),
            }
        },
    )

    return app


__all__ = ["create_app", "BaseConfig"]
