"""Structured logging with request correlation identifiers.

Production deployments emit newline delimited JSON so that log shippers can
parse records without regular expressions. Development keeps a readable
console format. Every request is tagged with a request id that is echoed back
to the client in the ``X-Request-ID`` response header.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import sys
import uuid
from contextvars import ContextVar
from pathlib import Path

request_id_var: ContextVar[str] = ContextVar("request_id", default="-")
user_agent_var: ContextVar[str] = ContextVar("user_agent", default="-")

LOGGER_NAME = "sqlshield"


class RequestIdFilter(logging.Filter):
    """Attach the current request id to every record."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = request_id_var.get()
        record.user_agent = user_agent_var.get()
        return True


class JsonFormatter(logging.Formatter):
    """Render log records as single line JSON documents."""

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "timestamp": self.formatTime(record, "%Y-%m-%dT%H:%M:%S%z"),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": getattr(record, "request_id", "-"),
        }

        if record.exc_info:
            payload["exception"] = self.formatException(record.exc_info)

        for key, value in getattr(record, "context", {}).items():
            payload[key] = value

        # The message doubles as the event name unless the context provided
        # one, so an explicit value is never silently overwritten.
        if record.name == LOGGER_NAME and record.getMessage():
            payload.setdefault("event", record.getMessage())

        return json.dumps(payload, default=str)


class ConsoleFormatter(logging.Formatter):
    """Readable console output for local development."""

    default_fmt = "%(asctime)s %(levelname)-8s [%(request_id)s] %(name)s: %(message)s"

    def __init__(self) -> None:
        super().__init__(self.default_fmt, "%H:%M:%S")


def configure_logging(app=None) -> logging.Logger:
    """Configure the application logger and return it."""
    level_name = "INFO"
    use_json = False
    log_dir = ""
    max_bytes = 5 * 1024 * 1024
    backup_count = 5

    if app is not None:
        level_name = app.config.get("LOG_LEVEL", "INFO")
        use_json = bool(app.config.get("LOG_JSON", False))
        log_dir = app.config.get("LOG_DIR", "") or ""
        max_bytes = int(app.config.get("LOG_MAX_BYTES", max_bytes))
        backup_count = int(app.config.get("LOG_BACKUP_COUNT", backup_count))
    else:
        level_name = os.getenv("LOG_LEVEL", "INFO").upper()
        use_json = os.getenv("LOG_JSON", "false").lower() in {"1", "true", "yes"}

    level = getattr(logging, str(level_name).upper(), logging.INFO)

    logger = logging.getLogger(LOGGER_NAME)
    logger.setLevel(level)
    logger.propagate = False

    for handler in list(logger.handlers):
        logger.removeHandler(handler)
        handler.close()

    formatter = JsonFormatter() if use_json else ConsoleFormatter()

    stream_handler = logging.StreamHandler(stream=sys.stdout)
    stream_handler.setFormatter(formatter)
    stream_handler.addFilter(RequestIdFilter())
    logger.addHandler(stream_handler)

    if log_dir:
        log_path = Path(log_dir)
        log_path.mkdir(parents=True, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            log_path / "sqlshield.log",
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        file_handler.setFormatter(JsonFormatter() if use_json else formatter)
        file_handler.addFilter(RequestIdFilter())
        logger.addHandler(file_handler)

    if not logger.handlers:
        logger.addHandler(logging.NullHandler())

    return logger


def get_logger(name: str | None = None) -> logging.Logger:
    """Return the shared application logger, or a child of it."""
    if name:
        return logging.getLogger(f"{LOGGER_NAME}.{name}")
    return logging.getLogger(LOGGER_NAME)


def new_request_id() -> str:
    return uuid.uuid4().hex


def log_event(logger: logging.Logger, level: int, message: str, **context) -> None:
    """Emit a log record carrying a structured ``context`` payload."""
    logger.log(level, message, extra={"context": context})
