"""Tests for the single page application.

The interface is plain HTML and JavaScript, so there is no framework to lean
on. These tests guard the contracts that are easy to break by hand: the
elements the script expects must exist, and the endpoints it calls must be
registered on the application.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE = PROJECT_ROOT / "templates" / "index.html"

SCRIPT_PATTERN = re.compile(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>", re.DOTALL)
ELEMENT_ID_PATTERN = re.compile(r'id="([^"]+)"')
GET_ELEMENT_PATTERN = re.compile(r"getElementById\(\s*['\"]([^'\"]+)['\"]\s*\)")
FETCH_PATTERN = re.compile(r"fetch\(\s*['\"]([^'\"]+)['\"]")


@pytest.fixture(scope="module")
def template() -> str:
    return TEMPLATE.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def script(template: str) -> str:
    blocks = SCRIPT_PATTERN.findall(template)
    assert blocks, "the template must contain an inline script"
    return "\n".join(blocks)


class TestTemplate:
    def test_the_template_exists(self):
        assert TEMPLATE.is_file()

    def test_the_script_is_balanced(self, script: str):
        assert script.count("{") == script.count("}")
        assert script.count("(") == script.count(")")

    def test_the_script_defines_the_expected_functions(self, script: str):
        for name in (
            "showPage",
            "loadDashboard",
            "renderDashboard",
            "renderChart",
            "renderTimeline",
            "loadLiveFeed",
            "renderLiveFeed",
            "checkHealth",
            "toggleAutoRefresh",
            "runScanner",
            "renderScanResult",
        ):
            assert f"function {name}(" in script, f"{name} is missing"


class TestDomContract:
    """Every element the script reaches for must exist in the markup."""

    def test_every_referenced_element_exists(self, template: str, script: str):
        markup_ids = set(ELEMENT_ID_PATTERN.findall(template))
        script_ids = set(GET_ELEMENT_PATTERN.findall(script))

        missing = sorted(script_ids - markup_ids)

        assert not missing, f"the script targets missing elements: {missing}"

    def test_the_core_sections_are_present(self, template: str):
        for element_id in (
            "statusStrip",
            "dbStatus",
            "encStatus",
            "requestIdLabel",
            "securityChart",
            "timelineChart",
            "liveFeedTable",
            "recordsTable",
            "attackTable",
            "registerForm",
            "scannerForm",
            "scannerValue",
            "scannerField",
            "scannerResult",
            "refreshBtn",
            "autoRefreshBtn",
        ):
            assert f'id="{element_id}"' in template


class TestApiContract:
    """Every endpoint the script calls must be registered on the app."""

    def test_every_fetched_path_is_registered(self, app, script: str):
        paths = {path for path in FETCH_PATTERN.findall(script) if path.startswith("/")}

        registered = {rule.rule for rule in app.url_map.iter_rules()}

        # The dashboard fetches a query string in one place, strip it.
        normalised = {path.split("?")[0] for path in paths}

        missing = sorted(path for path in normalised if path not in registered)

        assert not missing, f"the script calls unknown endpoints: {missing}"

    def test_the_script_uses_the_versioned_endpoints(self, script: str):
        assert "/api/v1/register" in script
        assert "/api/v1/dashboard" in script
        assert "/api/v1/security/events" in script
        assert "/api/v1/security/detect" in script

    def test_the_health_endpoint_is_polled(self, script: str):
        assert "/health/ready" in script


class TestSecurity:
    def test_no_payload_is_rendered_from_the_event_feed(self, script: str):
        """The live feed must never expose the stored payload."""
        feed = script[script.find("function renderLiveFeed") :]
        feed = feed[: feed.find("function ", 10)]

        assert "payload" not in feed

    def test_the_page_does_not_inline_secrets(self, template: str):
        for marker in ("MONGO_URI", "AES_KEY", "CAPABILITY_CODE"):
            assert marker not in template
