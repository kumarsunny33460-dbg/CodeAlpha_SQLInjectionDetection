"""Compatibility shim for the original ``database`` module.

The data layer now lives in :mod:`sqlshield.db`. The helper functions below
keep the original import path working.

Unlike the original implementation the connection is established lazily, so
importing this module never blocks or fails when the database is unreachable.
"""

from __future__ import annotations

import os
from typing import Any

from dotenv import load_dotenv

from sqlshield.db.mongo import DatabaseUnavailable, build_client
from sqlshield.db.repositories import (
    EVENT_SQL_INJECTION,
    EVENT_SYSTEM,
    EVENT_UNAUTHORIZED_ACCESS,
    EventRepository,
    SecurityEvent,
    UserRepository,
)

load_dotenv()

MONGO_URI = os.getenv("MONGO_URI")
DATABASE_NAME = os.getenv("DATABASE_NAME", "SQLInjectionSecurity")
COLLECTION_NAME = os.getenv("COLLECTION_NAME", "SecureUsers")
EVENTS_COLLECTION = os.getenv("EVENTS_COLLECTION", "AttackLogs")

_LEGACY_EVENT_TYPES = {
    "SQL Injection Attempt": EVENT_SQL_INJECTION,
    "Unauthorized Access Attempt": EVENT_UNAUTHORIZED_ACCESS,
}

_manager = None
_users: UserRepository | None = None
_events: EventRepository | None = None


def _connect():
    """Create the client and repositories on first use."""
    global _manager, _users, _events

    if _manager is not None:
        return _manager

    if not MONGO_URI:
        raise DatabaseUnavailable(
            "MONGO_URI is missing. Please add it to your .env file."
        )

    _manager = build_client(_SimpleConfig())
    database = _manager[DATABASE_NAME]

    _users = UserRepository(database[COLLECTION_NAME])
    _events = EventRepository(database[EVENTS_COLLECTION])

    return _manager


class _SimpleConfig:
    """Minimal configuration object consumed by the client factory."""

    MONGO_URI = MONGO_URI
    MONGO_CONNECT_TIMEOUT_MS = int(os.getenv("MONGO_CONNECT_TIMEOUT_MS", 5000))
    MONGO_SERVER_SELECTION_TIMEOUT_MS = int(
        os.getenv("MONGO_SERVER_SELECTION_TIMEOUT_MS", 5000)
    )
    MONGO_SOCKET_TIMEOUT_MS = int(os.getenv("MONGO_SOCKET_TIMEOUT_MS", 10000))
    MONGO_MAX_POOL_SIZE = int(os.getenv("MONGO_MAX_POOL_SIZE", 50))
    MONGO_MIN_POOL_SIZE = int(os.getenv("MONGO_MIN_POOL_SIZE", 1))
    MONGO_RETRY_WRITES = os.getenv("MONGO_RETRY_WRITES", "true").lower() in {
        "1",
        "true",
        "yes",
    }


def _require_users() -> UserRepository:
    _connect()
    assert _users is not None
    return _users


def _require_events() -> EventRepository:
    _connect()
    assert _events is not None
    return _events


def save_user(user_data: dict[str, Any]):
    """Insert a user record using the legacy dictionary shape."""
    payload = dict(user_data)

    name = payload.pop("name", "")
    email = payload.pop("email", "")
    password = payload.pop("password", "")
    password_hash = payload.pop("password_hash", None)

    if not password_hash:
        from sqlshield.security.crypto import hash_password

        password_hash = hash_password(password)

    payload.setdefault("security_status", "AES-256 Encrypted")

    record_id = _require_users().create(
        name=name,
        email=email,
        password_hash=password_hash,
        extra=payload,
    )

    return {"acknowledged": True, "inserted_id": record_id}


def save_attack_log(payload, attack_type, source):
    """Record a security event using the legacy argument names."""
    event_type = _LEGACY_EVENT_TYPES.get(attack_type, EVENT_SYSTEM)

    event_id = _require_events().record(
        SecurityEvent(
            event_type=event_type,
            source=source,
            payload=str(payload),
            category=attack_type,
        )
    )

    return {"acknowledged": True, "inserted_id": event_id}


def get_dashboard_data() -> dict[str, Any]:
    """Return the dashboard payload using the legacy shape."""
    users = _require_users()
    events = _require_events()
    counts = events.counts_by_type()

    return {
        "statistics": {
            "total_users": users.count(),
            "sql_attacks": counts.get(EVENT_SQL_INJECTION, 0),
            "unauthorized_attempts": counts.get(EVENT_UNAUTHORIZED_ACCESS, 0),
            "security_events": sum(counts.values()),
        },
        "recent_users": users.recent(limit=8),
        "recent_logs": events.recent(limit=8),
    }


__all__ = [
    "DATABASE_NAME",
    "COLLECTION_NAME",
    "EVENTS_COLLECTION",
    "MONGO_URI",
    "get_dashboard_data",
    "save_attack_log",
    "save_user",
]
