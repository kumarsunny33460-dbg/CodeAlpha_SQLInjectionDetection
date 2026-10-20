"""Environment driven configuration for the SQLShield application.

Configuration is resolved once, at application creation time, from the process
environment. Nothing in this module performs network access, so the package can
be imported in environments without a database connection.
"""

from __future__ import annotations

import os
from typing import Any

from dotenv import load_dotenv

# The environment file has to be loaded before the configuration classes are
# evaluated below, because every setting is resolved at import time. Real
# environment variables always take precedence over the file.
load_dotenv()

TRUTHY = {"1", "true", "yes", "on"}
FALSY = {"0", "false", "no", "off"}


def env_str(name: str, default: str = "") -> str:
    value = os.getenv(name)
    if value is None:
        return default
    return value.strip()


def env_bool(name: str, default: bool = False) -> bool:
    value = env_str(name).lower()
    if not value:
        return default
    if value in TRUTHY:
        return True
    if value in FALSY:
        return False
    return default


def env_int(name: str, default: int) -> int:
    value = env_str(name)
    if not value:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def env_list(name: str, default: list[str] | None = None) -> list[str]:
    raw = env_str(name)
    if not raw:
        return list(default or [])
    return [item.strip() for item in raw.split(",") if item.strip()]


def env_cors_origins() -> list[str]:
    """Allowed origins. Defaults to same-origin only, which is the safe choice."""
    return env_list("CORS_ORIGINS", [])


def config_value(config, key: str, default=None):
    """Read ``key`` from a Flask config object, a mapping or a class.

    ``app.config`` is a dictionary subclass, so attribute access does not
    work on it, while configuration classes only expose attributes. This
    helper accepts either.
    """
    if config is None:
        return default

    try:
        return config[key]
    except (KeyError, TypeError, IndexError):
        pass

    return getattr(config, key, default)


class BaseConfig:
    """Settings shared by every environment."""

    APP_NAME = "SQLShield"
    APP_VERSION = "2.0.0"

    # ---------------------------------------------------------------
    # Core Flask
    # ---------------------------------------------------------------
    SECRET_KEY = env_str("SECRET_KEY")
    JSON_SORT_KEYS = False
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_SECURE = env_bool("SESSION_COOKIE_SECURE", False)
    PERMANENT_SESSION_LIFETIME = 3600

    MAX_CONTENT_LENGTH = env_int("MAX_CONTENT_LENGTH", 64 * 1024)
    PROPAGATE_EXCEPTIONS = False
    TESTING = False
    DEBUG = False

    # ---------------------------------------------------------------
    # Database
    # ---------------------------------------------------------------
    MONGO_URI = env_str("MONGO_URI")
    DATABASE_NAME = env_str("DATABASE_NAME", "SQLInjectionSecurity")
    USERS_COLLECTION = env_str("COLLECTION_NAME", "SecureUsers")
    EVENTS_COLLECTION = env_str("EVENTS_COLLECTION", "AttackLogs")
    MONGO_CONNECT_TIMEOUT_MS = env_int("MONGO_CONNECT_TIMEOUT_MS", 5000)
    MONGO_SERVER_SELECTION_TIMEOUT_MS = env_int("MONGO_SERVER_SELECTION_TIMEOUT_MS", 5000)
    MONGO_SOCKET_TIMEOUT_MS = env_int("MONGO_SOCKET_TIMEOUT_MS", 10000)
    MONGO_MAX_POOL_SIZE = env_int("MONGO_MAX_POOL_SIZE", 50)
    MONGO_MIN_POOL_SIZE = env_int("MONGO_MIN_POOL_SIZE", 1)
    MONGO_RETRY_WRITES = env_bool("MONGO_RETRY_WRITES", True)
    MONGO_AUTO_INDEX = env_bool("MONGO_AUTO_INDEX", True)

    # ---------------------------------------------------------------
    # Security material
    # ---------------------------------------------------------------
    # "kid:base64key" pairs. The first entry is the active encryption key.
    AES_KEYS = env_list("AES_KEYS", [])
    # Legacy single key, kept for backwards compatibility with v1 deployments.
    AES_KEY = env_str("AES_KEY")
    ACTIVE_KEY_ID = env_str("ACTIVE_KEY_ID", "v1")
    # Optional stable key used to derive the email lookup fingerprint. When it
    # is not set the fingerprint is derived from the active AES key, which
    # means the fingerprints change when the encryption key is rotated.
    FINGERPRINT_KEY = env_str("FINGERPRINT_KEY")

    CAPABILITY_CODES = env_list("CAPABILITY_CODES", [])
    CAPABILITY_CODE = env_str("CAPABILITY_CODE")
    CAPABILITY_CODE_SHA256 = env_str("CAPABILITY_CODE_SHA256")
    CAPABILITY_MAX_ATTEMPTS = env_int("CAPABILITY_MAX_ATTEMPTS", 5)
    CAPABILITY_LOCKOUT_SECONDS = env_int("CAPABILITY_LOCKOUT_SECONDS", 300)

    PBKDF2_ITERATIONS = env_int("PBKDF2_ITERATIONS", 600_000)
    PBKDF2_SALT_BYTES = env_int("PBKDF2_SALT_BYTES", 16)

    # ---------------------------------------------------------------
    # Detection engine
    # ---------------------------------------------------------------
    SQLI_BLOCK_THRESHOLD = env_int("SQLI_BLOCK_THRESHOLD", 40)
    SQLI_MAX_FIELD_LENGTH = env_int("SQLI_MAX_FIELD_LENGTH", 512)
    SQLI_LOG_PAYLOAD_MAX = env_int("SQLI_LOG_PAYLOAD_MAX", 500)

    # ---------------------------------------------------------------
    # Rate limiting
    # ---------------------------------------------------------------
    RATELIMIT_ENABLED = env_bool("RATELIMIT_ENABLED", True)
    RATELIMIT_STORAGE_URI = env_str("RATELIMIT_STORAGE_URI", "memory://")
    RATELIMIT_DEFAULT = env_str("RATELIMIT_DEFAULT", "120 per minute")
    RATELIMIT_REGISTRATION = env_str("RATELIMIT_REGISTRATION", "10 per minute")
    RATELIMIT_DASHBOARD = env_str("RATELIMIT_DASHBOARD", "60 per minute")

    # ---------------------------------------------------------------
    # Security headers / CORS
    # ---------------------------------------------------------------
    TALISMAN_ENABLED = env_bool("TALISMAN_ENABLED", True)
    TALISMAN_FORCE_HTTPS = env_bool("TALISMAN_FORCE_HTTPS", True)
    TALISMAN_CSP = env_str(
        "TALISMAN_CSP",
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net "
        "https://cdnjs.cloudflare.com https://fonts.googleapis.com; "
        "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com; "
        "img-src 'self' data:; "
        "connect-src 'self'",
    )
    CORS_ORIGINS = env_cors_origins()

    # ---------------------------------------------------------------
    # Logging
    # ---------------------------------------------------------------
    LOG_LEVEL = env_str("LOG_LEVEL", "INFO").upper()
    LOG_JSON = env_bool("LOG_JSON", False)
    LOG_DIR = env_str("LOG_DIR", "")
    LOG_MAX_BYTES = env_int("LOG_MAX_BYTES", 5 * 1024 * 1024)
    LOG_BACKUP_COUNT = env_int("LOG_BACKUP_COUNT", 5)
    LOG_REQUESTS = env_bool("LOG_REQUESTS", True)

    # ---------------------------------------------------------------
    # Operations
    # ---------------------------------------------------------------
    HEALTH_CHECK_INTERVAL_SECONDS = env_int("HEALTH_CHECK_INTERVAL_SECONDS", 30)
    TRUSTED_PROXY_COUNT = env_int("TRUSTED_PROXY_COUNT", 1)
    PORT = env_int("PORT", 5000)

    @classmethod
    def as_dict(cls) -> dict[str, Any]:
        return {
            key: getattr(cls, key)
            for key in dir(cls)
            if key.isupper() and not key.startswith("_")
        }


class DevelopmentConfig(BaseConfig):
    DEBUG = True
    LOG_LEVEL = env_str("LOG_LEVEL", "DEBUG").upper()
    LOG_JSON = env_bool("LOG_JSON", False)
    TALISMAN_ENABLED = env_bool("TALISMAN_ENABLED", False)
    TALISMAN_FORCE_HTTPS = False
    RATELIMIT_ENABLED = env_bool("RATELIMIT_ENABLED", False)


class TestingConfig(BaseConfig):
    TESTING = True
    DEBUG = False
    SECRET_KEY = env_str("SECRET_KEY", "testing-secret-key")
    MONGO_URI = env_str("MONGO_URI", "mongomock://localhost")
    LOG_LEVEL = env_str("LOG_LEVEL", "WARNING").upper()
    RATELIMIT_ENABLED = False
    TALISMAN_ENABLED = False
    TALISMAN_FORCE_HTTPS = False
    PBKDF2_ITERATIONS = env_int("PBKDF2_ITERATIONS", 1_000)
    AES_KEY = env_str("AES_KEY") or "dGVzdC1rZXktZm9yLXVuaXQtdGVzdHMta2V5LTAwMDA="


class ProductionConfig(BaseConfig):
    DEBUG = False
    LOG_JSON = env_bool("LOG_JSON", True)
    SESSION_COOKIE_SECURE = env_bool("SESSION_COOKIE_SECURE", True)
    PROPAGATE_EXCEPTIONS = False


CONFIGS = {
    "development": DevelopmentConfig,
    "testing": TestingConfig,
    "production": ProductionConfig,
    "default": DevelopmentConfig,
}


def resolve_config(name: str | None = None):
    """Return the configuration class matching ``name`` or the environment."""
    key = (name or env_str("FLASK_ENV", "development")).lower()
    return CONFIGS.get(key, DevelopmentConfig)
