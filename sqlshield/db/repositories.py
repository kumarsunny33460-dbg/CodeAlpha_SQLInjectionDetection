"""Repositories encapsulating the MongoDB collections.

Keeping persistence logic out of the API layer makes the HTTP surface testable
and keeps query shapes in a single place.
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from pymongo.errors import DuplicateKeyError

# ---------------------------------------------------------------------
# Event vocabulary
# ---------------------------------------------------------------------
EVENT_SQL_INJECTION = "sql_injection"
EVENT_UNAUTHORIZED_ACCESS = "unauthorized_access"
EVENT_VALIDATION_ERROR = "validation_error"
EVENT_SYSTEM = "system"

EVENT_LABELS = {
    EVENT_SQL_INJECTION: "SQL Injection Attempt",
    EVENT_UNAUTHORIZED_ACCESS: "Unauthorized Access Attempt",
    EVENT_VALIDATION_ERROR: "Validation Error",
    EVENT_SYSTEM: "Security Event",
}

EVENT_SEVERITIES = {
    EVENT_SQL_INJECTION: "high",
    EVENT_UNAUTHORIZED_ACCESS: "medium",
    EVENT_VALIDATION_ERROR: "low",
    EVENT_SYSTEM: "info",
}


def label_for(event_type: str) -> str:
    return EVENT_LABELS.get(event_type, "Security Event")


def severity_for_event(event_type: str) -> str:
    return EVENT_SEVERITIES.get(event_type, "info")


@dataclass
class SecurityEvent:
    """A security event ready to be persisted."""

    event_type: str
    source: str = "Unknown"
    payload: str = ""
    category: str = ""
    severity: str = ""
    score: int = 0
    ip_address: str = ""
    user_agent: str = ""
    request_id: str = ""
    details: dict[str, Any] = field(default_factory=dict)

    def to_document(self) -> dict[str, Any]:
        return {
            "event_type": self.event_type,
            "label": label_for(self.event_type),
            "category": self.category or self.event_type,
            "severity": self.severity or severity_for_event(self.event_type),
            "score": int(self.score),
            "source": self.source,
            "payload": str(self.payload)[:500],
            "ip_address": self.ip_address,
            "user_agent": str(self.user_agent)[:300],
            "request_id": self.request_id,
            "details": self.details,
            "timestamp": datetime.now(UTC),
        }


class UserRepository:
    """Access to the encrypted user records."""

    def __init__(
        self,
        collection: Any,
        fingerprint_key: bytes | None = None,
    ) -> None:
        self.collection = collection
        self._fingerprint_key = fingerprint_key or b"sqlshield-fingerprint"

    # -----------------------------------------------------------------
    # Helpers
    # -----------------------------------------------------------------
    def fingerprint(self, email: str) -> str:
        """Return a keyed, non reversible fingerprint of ``email``."""
        normalised = str(email or "").strip().lower().encode("utf-8")
        return hmac.new(
            self._fingerprint_key,
            normalised,
            hashlib.sha256,
        ).hexdigest()

    # -----------------------------------------------------------------
    # Operations
    # -----------------------------------------------------------------
    def create(
        self,
        name: str,
        email: str,
        password_hash: str,
        email_plain: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> str:
        """Insert an encrypted user record and return its identifier.

        ``email`` is the encrypted value that is stored, ``email_plain`` is
        the clear text address used to derive the lookup fingerprint. The
        fingerprint must never be derived from the ciphertext because every
        encryption uses a fresh nonce.
        """
        document = {
            "name": name,
            "email": email,
            "email_fingerprint": self.fingerprint(
                email_plain if email_plain is not None else email
            ),
            "password_hash": password_hash,
            "security_status": "AES-256 Encrypted",
            "schema_version": 2,
            "created_at": datetime.now(UTC),
        }

        if extra:
            document.update(extra)

        result = self.collection.insert_one(document)
        return str(result.inserted_id)

    def exists(self, email: str) -> bool:
        return (
            self.collection.count_documents(
                {"email_fingerprint": self.fingerprint(email)},
                limit=1,
            )
            > 0
        )

    def count(self) -> int:
        return self.collection.count_documents({})

    def recent(self, limit: int = 8) -> list[dict[str, Any]]:
        cursor = (
            self.collection.find(
                {},
                {
                    "name": 0,
                    "email": 0,
                    "password_hash": 0,
                    "email_fingerprint": 0,
                },
            )
            .sort("created_at", -1)
            .limit(limit)
        )

        records = []
        for index, document in enumerate(cursor, start=1):
            created_at = document.get("created_at")
            records.append(
                {
                    "number": index,
                    "id": str(document.get("_id")),
                    "status": document.get("security_status", "Encrypted"),
                    "created_at": format_timestamp(created_at),
                }
            )

        return records


class EventRepository:
    """Access to the security event log."""

    def __init__(self, collection: Any) -> None:
        self.collection = collection

    # -----------------------------------------------------------------
    # Operations
    # -----------------------------------------------------------------
    def record(self, event: SecurityEvent) -> str:
        result = self.collection.insert_one(event.to_document())
        return str(result.inserted_id)

    def count(self, event_type: str | None = None) -> int:
        if event_type is None:
            return self.collection.count_documents({})
        return self.collection.count_documents({"event_type": event_type})

    def counts_by_type(self) -> dict[str, int]:
        pipeline: list[dict[str, Any]] = [
            {"$group": {"_id": "$event_type", "total": {"$sum": 1}}},
        ]

        try:
            rows = list(self.collection.aggregate(pipeline))
        except Exception:  # noqa: BLE001 - fall back to a portable scan
            counts: dict[str, int] = {}
            for document in self.collection.find({}, {"event_type": 1}):
                key = document.get("event_type", EVENT_SYSTEM)
                counts[key] = counts.get(key, 0) + 1
            return counts

        return {row["_id"]: row["total"] for row in rows if row.get("_id")}

    def recent(self, limit: int = 8) -> list[dict[str, Any]]:
        cursor = (
            self.collection.find(
                {},
                {
                    "payload": 0,
                    "ip_address": 0,
                    "user_agent": 0,
                    "details": 0,
                },
            )
            .sort("timestamp", -1)
            .limit(limit)
        )

        events = []
        for document in cursor:
            events.append(
                {
                    "event_type": document.get("event_type", EVENT_SYSTEM),
                    "attack_type": document.get(
                        "label",
                        label_for(document.get("event_type", EVENT_SYSTEM)),
                    ),
                    "category": document.get("category", ""),
                    "severity": document.get("severity", "info"),
                    "score": document.get("score", 0),
                    "source": document.get("source", "Unknown"),
                    "timestamp": format_timestamp(document.get("timestamp")),
                    "request_id": document.get("request_id", ""),
                }
            )

        return events

    def timeline(self, days: int = 7) -> list[dict[str, Any]]:
        """Return daily event counts for the last ``days`` days."""
        days = max(1, min(int(days), 90))
        start = datetime.now(UTC) - timedelta(days=days - 1)

        pipeline: list[dict[str, Any]] = [
            {"$match": {"timestamp": {"$gte": start}}},
            {
                "$group": {
                    "_id": {
                        "$dateToString": {
                            "format": "%Y-%m-%d",
                            "date": "$timestamp",
                        }
                    },
                    "total": {"$sum": 1},
                }
            },
            {"$sort": {"_id": 1}},
        ]

        try:
            rows = list(self.collection.aggregate(pipeline))
            return [
                {"date": row["_id"], "total": row["total"]}
                for row in rows
                if row.get("_id")
            ]
        except Exception:  # noqa: BLE001 - portable fallback
            buckets: dict[str, int] = {}
            for document in self.collection.find(
                {"timestamp": {"$gte": start}},
                {"timestamp": 1},
            ):
                timestamp = document.get("timestamp")
                if not timestamp:
                    continue
                key = timestamp.strftime("%Y-%m-%d")
                buckets[key] = buckets.get(key, 0) + 1
            return [{"date": key, "total": buckets[key]} for key in sorted(buckets)]

    def top_attack_categories(self, limit: int = 5) -> list[dict[str, Any]]:
        """Return the most frequent attack categories."""
        pipeline: list[dict[str, Any]] = [
            {"$match": {"event_type": EVENT_SQL_INJECTION}},
            {"$group": {"_id": "$category", "total": {"$sum": 1}}},
            {"$sort": {"total": -1}},
            {"$limit": limit},
        ]

        try:
            rows = list(self.collection.aggregate(pipeline))
        except Exception:  # noqa: BLE001
            rows = []

        return [
            {"category": row["_id"], "total": row["total"]}
            for row in rows
            if row.get("_id")
        ]


def format_timestamp(value: Any) -> str:
    """Render a datetime in the format used across the dashboard."""
    if isinstance(value, datetime):
        return value.strftime("%d %b %Y, %I:%M %p")
    return "N/A"


def duplicate_key_error(exc: DuplicateKeyError) -> bool:
    return isinstance(exc, DuplicateKeyError)


__all__ = [
    "EVENT_LABELS",
    "EVENT_SEVERITIES",
    "EVENT_SQL_INJECTION",
    "EVENT_SYSTEM",
    "EVENT_UNAUTHORIZED_ACCESS",
    "EVENT_VALIDATION_ERROR",
    "EventRepository",
    "SecurityEvent",
    "UserRepository",
    "format_timestamp",
    "label_for",
    "severity_for_event",
]
