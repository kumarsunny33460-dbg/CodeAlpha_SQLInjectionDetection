"""Data access layer for SQLShield."""

from __future__ import annotations

from .mongo import DatabaseUnavailable, MongoManager, mongo
from .repositories import (
    EVENT_SEVERITIES,
    EVENT_SQL_INJECTION,
    EVENT_SYSTEM,
    EVENT_UNAUTHORIZED_ACCESS,
    EVENT_VALIDATION_ERROR,
    EventRepository,
    SecurityEvent,
    UserRepository,
    format_timestamp,
)

__all__ = [
    "DatabaseUnavailable",
    "EVENT_SEVERITIES",
    "EVENT_SQL_INJECTION",
    "EVENT_SYSTEM",
    "EVENT_UNAUTHORIZED_ACCESS",
    "EVENT_VALIDATION_ERROR",
    "EventRepository",
    "MongoManager",
    "SecurityEvent",
    "UserRepository",
    "format_timestamp",
    "mongo",
]
