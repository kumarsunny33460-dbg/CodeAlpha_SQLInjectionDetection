"""MongoDB connection management.

The client is created lazily so that the application can boot, serve health
checks and report a degraded state even when the database is unreachable.
Connections are pooled, time bounded and retried.
"""

from __future__ import annotations

from typing import Any

from pymongo import MongoClient
from pymongo.collection import Collection
from pymongo.database import Database
from pymongo.errors import PyMongoError

from ..config import config_value
from ..logging_config import get_logger

logger = get_logger("db")


class DatabaseUnavailable(RuntimeError):
    """Raised when the database cannot be reached."""


class UnavailableCollection:
    """Placeholder used when the database is not configured.

    Every operation raises so that a misconfigured deployment fails loudly
    instead of silently returning empty data.
    """

    def __init__(self, reason: str = "The database is not configured.") -> None:
        self.reason = reason

    def _fail(self, *args, **kwargs):
        raise DatabaseUnavailable(self.reason)

    __getattr__ = _fail


def build_client(config) -> Any:
    uri = config_value(config, "MONGO_URI", "") or ""

    if uri.startswith("mongomock://"):
        import mongomock  # imported lazily, it is a development dependency

        client: Any = mongomock.MongoClient()
        logger.info("Using the in-memory mongomock client")
        return client

    if not uri:
        raise DatabaseUnavailable("MONGO_URI is not configured.")

    return MongoClient(
        uri,
        serverSelectionTimeoutMS=config_value(
            config, "MONGO_SERVER_SELECTION_TIMEOUT_MS", 5000
        ),
        connectTimeoutMS=config_value(config, "MONGO_CONNECT_TIMEOUT_MS", 5000),
        socketTimeoutMS=config_value(config, "MONGO_SOCKET_TIMEOUT_MS", 10000),
        maxPoolSize=config_value(config, "MONGO_MAX_POOL_SIZE", 50),
        minPoolSize=config_value(config, "MONGO_MIN_POOL_SIZE", 1),
        retryWrites=bool(config_value(config, "MONGO_RETRY_WRITES", True)),
        appname="sqlshield",
        tz_aware=True,
    )


class MongoManager:
    """Owns the MongoDB client and exposes the application collections."""

    def __init__(self) -> None:
        self._client: Any | None = None
        self._database: Database | None = None
        self._config: Any | None = None
        self._connected = False
        self._last_error = ""

    # -----------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------
    def init_app(self, app) -> None:
        config = app.config
        self._config = config
        app.extensions["mongo"] = self

        try:
            self._client = build_client(config)
            self._database = self._client[config["DATABASE_NAME"]]
        except Exception as error:  # noqa: BLE001 - the app must still boot
            self._client = None
            self._database = None
            self._connected = False
            self._last_error = str(error)
            logger.error(
                "Database is not available",
                extra={"context": {"error": str(error)}},
            )
            return

        if config.get("MONGO_AUTO_INDEX", True):
            self.ensure_indexes()

        self.ping()
        logger.info(
            "Database configured",
            extra={"context": {"database": config["DATABASE_NAME"]}},
        )

    @property
    def client(self) -> Any:
        if self._client is None:
            raise DatabaseUnavailable("The database client has not been initialised.")
        return self._client

    @property
    def database(self) -> Database:
        if self._database is None:
            raise DatabaseUnavailable("The database has not been initialised.")
        return self._database

    @property
    def is_connected(self) -> bool:
        return self._connected

    @property
    def last_error(self) -> str:
        return self._last_error

    # -----------------------------------------------------------------
    # Collections
    # -----------------------------------------------------------------
    def collection(self, name: str) -> Collection:
        return self.database[name]

    @property
    def users(self) -> Collection:
        return self.collection(self._config_value("USERS_COLLECTION", "SecureUsers"))

    @property
    def events(self) -> Collection:
        return self.collection(self._config_value("EVENTS_COLLECTION", "AttackLogs"))

    def _config_value(self, key: str, default: str) -> str:
        return config_value(self._config, key, default)

    # -----------------------------------------------------------------
    # Operations
    # -----------------------------------------------------------------
    def ensure_indexes(self) -> None:
        """Create the indexes required by the application queries."""
        try:
            self.users.create_index([("created_at", -1)], name="users_created_at")
            self.users.create_index(
                [("email_fingerprint", 1)],
                name="users_email_fingerprint",
                unique=True,
                sparse=True,
            )
            self.events.create_index([("timestamp", -1)], name="events_timestamp")
            self.events.create_index(
                [("event_type", 1), ("timestamp", -1)], name="events_type_time"
            )
            self.events.create_index([("request_id", 1)], name="events_request_id")
        except PyMongoError as error:
            logger.warning(
                "Unable to create database indexes",
                extra={"context": {"error": str(error)}},
            )

    def ping(self) -> bool:
        """Check the database connection and update the cached state."""
        if self._client is None:
            self._connected = False
            if not self._last_error:
                self._last_error = "The database client is not configured."
            return False

        try:
            self.client.admin.command("ping")
            self._connected = True
            self._last_error = ""
        except Exception as error:  # noqa: BLE001 - health checks must never raise
            self._connected = False
            self._last_error = str(error)
            logger.warning(
                "Database ping failed",
                extra={"context": {"error": str(error)}},
            )
        return self._connected

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:  # noqa: BLE001, S110 - shutdown must not raise
                pass
        self._client = None
        self._database = None
        self._connected = False


mongo = MongoManager()

__all__ = [
    "DatabaseUnavailable",
    "MongoManager",
    "UnavailableCollection",
    "build_client",
    "mongo",
]
