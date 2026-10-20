"""Tests for the structured logging layer."""

from __future__ import annotations

import json
import logging

import pytest

from sqlshield.logging_config import (
    ConsoleFormatter,
    JsonFormatter,
    RequestIdFilter,
    configure_logging,
    get_logger,
    log_event,
    new_request_id,
    request_id_var,
    user_agent_var,
)


@pytest.fixture()
def record() -> logging.LogRecord:
    entry = logging.LogRecord(
        name="sqlshield.test",
        level=logging.INFO,
        pathname=__file__,
        lineno=10,
        msg="request completed",
        args=(),
        exc_info=None,
    )
    entry.request_id = "abc123"
    entry.user_agent = "pytest"
    return entry


class TestJsonFormatter:
    def test_the_output_is_a_single_json_document(self, record):
        payload = json.loads(JsonFormatter().format(record))

        assert payload["level"] == "INFO"
        assert payload["logger"] == "sqlshield.test"
        assert payload["message"] == "request completed"
        assert payload["request_id"] == "abc123"

    def test_the_context_is_merged_into_the_payload(self, record):
        record.context = {"status": 200, "path": "/"}

        payload = json.loads(JsonFormatter().format(record))

        assert payload["status"] == 200
        assert payload["path"] == "/"

    def test_a_record_without_a_context_still_renders(self, record):
        payload = json.loads(JsonFormatter().format(record))

        assert "status" not in payload

    def test_the_output_contains_no_newlines(self, record):
        rendered = JsonFormatter().format(record)

        assert "\n" not in rendered
        assert len(rendered.splitlines()) == 1

    def test_unserialisable_values_do_not_break_the_formatter(self, record):
        record.context = {"value": object()}

        payload = json.loads(JsonFormatter().format(record))

        assert "value" in payload


class TestRequestIdFilter:
    def test_the_current_request_id_is_attached(self, record):
        token = request_id_var.set("request-42")

        try:
            assert RequestIdFilter().filter(record) is True
            assert record.request_id == "request-42"
        finally:
            request_id_var.reset(token)

    def test_the_request_id_always_appears_in_the_output(self, record):
        del record.request_id

        payload = json.loads(JsonFormatter().format(record))

        assert "request_id" in payload


class TestConsoleFormatter:
    def test_the_request_id_appears_in_the_output(self, record):
        rendered = ConsoleFormatter().format(record)

        assert "abc123" in rendered
        assert "request completed" in rendered


class TestConfigureLogging:
    def test_the_application_logger_is_configured(self, app):
        logger = configure_logging(app)

        assert logger.name == "sqlshield"
        assert logger.handlers
        assert logger.level in {
            logging.INFO,
            logging.DEBUG,
            logging.WARNING,
            logging.ERROR,
        }

    def test_configuring_twice_does_not_duplicate_the_handlers(self, app):
        first = configure_logging(app)
        count = len(first.handlers)

        second = configure_logging(app)

        assert len(second.handlers) == count

    def test_json_output_is_selected_by_the_configuration(self, app):
        app.config["LOG_JSON"] = True

        logger = configure_logging(app)

        assert isinstance(logger.handlers[0].formatter, JsonFormatter)

    def test_a_log_file_is_written_when_a_directory_is_configured(self, app, tmp_path):
        app.config["LOG_DIR"] = str(tmp_path)
        app.config["LOG_JSON"] = True
        app.config["LOG_LEVEL"] = "INFO"

        logger = configure_logging(app)

        log_event(logger, logging.INFO, "file logging works", event="test")

        for handler in logger.handlers:
            handler.flush()

        contents = (tmp_path / "sqlshield.log").read_text(encoding="utf-8")

        assert "file logging works" in contents
        assert json.loads(contents.strip().splitlines()[-1])["event"] == "test"

    def test_the_application_logger_has_no_parent_handlers(self, app):
        logger = configure_logging(app)

        assert logger.propagate is False


class TestHelpers:
    def test_a_request_id_is_generated(self):
        assert len(new_request_id()) == 32

    def test_request_ids_are_unique(self):
        assert new_request_id() != new_request_id()

    def test_get_logger_returns_a_child_logger(self):
        child = get_logger("database")

        assert child.name == "sqlshield.database"

    def test_log_event_attaches_the_context(self, app):
        logger = configure_logging(app)
        app.config["LOG_LEVEL"] = "INFO"
        logger.setLevel(logging.INFO)

        captured = []

        class Capture(logging.Handler):
            def emit(self, record):
                captured.append(record)

        handler = Capture()
        logger.addHandler(handler)

        try:
            log_event(logger, logging.INFO, "careful", threat="sqli")
        finally:
            logger.removeHandler(handler)

        assert captured
        assert captured[-1].getMessage() == "careful"
        assert captured[-1].context == {"threat": "sqli"}

    def test_the_user_agent_is_tracked(self):
        token = user_agent_var.set("Mozilla/5.0")

        try:
            assert user_agent_var.get() == "Mozilla/5.0"
        finally:
            user_agent_var.reset(token)
