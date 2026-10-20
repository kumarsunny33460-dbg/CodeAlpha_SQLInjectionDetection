"""Flask extension singletons.

Extensions are created without an application and bound later inside the
application factory. Keeping them in one module avoids circular imports
between the factory, the blueprints and the extension objects themselves.
"""

from __future__ import annotations

from flask import current_app
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman


def _rate_limit_key() -> str:
    """Identify clients by forwarded IP when running behind a proxy."""
    return get_remote_address()


def _default_limit() -> str:
    """Resolve the default rate limit from the active configuration."""
    value = current_app.config.get("RATELIMIT_DEFAULT") or ""
    return value or "120 per minute"


limiter = Limiter(
    key_func=_rate_limit_key,
    default_limits=[_default_limit],
    headers_enabled=True,
    strategy="fixed-window",
)

talisman = Talisman(
    force_https=False,
    strict_transport_security=False,
    session_cookie_secure=False,
    referrer_policy="no-referrer",
    frame_options="DENY",
    content_security_policy=None,
)

cors = CORS()


def init_extensions(app) -> None:
    """Bind every extension to ``app`` using the resolved configuration."""
    limiter.enabled = bool(app.config.get("RATELIMIT_ENABLED", True))
    limiter.init_app(app)

    talisman.enabled = bool(app.config.get("TALISMAN_ENABLED", True))
    talisman.init_app(
        app,
        content_security_policy=app.config.get("TALISMAN_CSP"),
        force_https=bool(app.config.get("TALISMAN_FORCE_HTTPS", True)),
        strict_transport_security=bool(app.config.get("TALISMAN_FORCE_HTTPS", True)),
        session_cookie_secure=bool(app.config.get("SESSION_COOKIE_SECURE", False)),
        referrer_policy="no-referrer",
        frame_options="DENY",
        x_content_type_options=True,
    )

    origins = app.config.get("CORS_ORIGINS") or []
    cors.init_app(
        app,
        resources={r"/api/*": {"origins": origins}},
        supports_credentials=False,
        expose_headers=["X-Request-ID"],
        allow_headers=["Content-Type", "X-Request-ID"],
    )


__all__ = ["limiter", "talisman", "cors", "init_extensions"]
