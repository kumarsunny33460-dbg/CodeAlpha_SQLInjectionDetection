"""Tests for the configuration layer."""

from __future__ import annotations

import base64
import os
import subprocess
import sys
from pathlib import Path

import pytest

from sqlshield.config import (
    BaseConfig,
    DevelopmentConfig,
    ProductionConfig,
    TestingConfig,
    config_value,
    env_bool,
    env_int,
    env_list,
    env_str,
    resolve_config,
)
from sqlshield.security.crypto import CryptoError, KeyVault

PROJECT_ROOT = Path(__file__).resolve().parent.parent


def evaluate_config(env_overrides: dict[str, str], expression: str) -> str:
    """Evaluate an expression against a freshly imported configuration module.

    The configuration classes resolve the environment when the module is
    imported, so the only reliable way to test them is to import them again
    in a subprocess with a controlled environment.
    """
    environment = {
        **os.environ,
        "PYTHONPATH": str(PROJECT_ROOT),
        **env_overrides,
    }

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            f"import sqlshield.config as c; print({expression})",
        ],
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr

    return result.stdout.strip()


class TestEnvironmentHelpers:
    def test_env_str_returns_the_default_when_unset(self, monkeypatch):
        monkeypatch.delenv("SQLSHIELD_TEST_VALUE", raising=False)
        assert env_str("SQLSHIELD_TEST_VALUE", "fallback") == "fallback"

    def test_env_str_strips_the_value(self, monkeypatch):
        monkeypatch.setenv("SQLSHIELD_TEST_VALUE", "  value  ")
        assert env_str("SQLSHIELD_TEST_VALUE") == "value"

    def test_env_bool_accepts_the_truthy_values(self, monkeypatch):
        for raw in ("1", "true", "YES", "on"):
            monkeypatch.setenv("SQLSHIELD_TEST_FLAG", raw)
            assert env_bool("SQLSHIELD_TEST_FLAG") is True

    def test_env_bool_accepts_the_falsy_values(self, monkeypatch):
        for raw in ("0", "false", "no", "off"):
            monkeypatch.setenv("SQLSHIELD_TEST_FLAG", raw)
            assert env_bool("SQLSHIELD_TEST_FLAG") is False

    def test_env_bool_falls_back_on_a_bad_value(self, monkeypatch):
        monkeypatch.setenv("SQLSHIELD_TEST_FLAG", "maybe")
        assert env_bool("SQLSHIELD_TEST_FLAG", True) is True

    def test_env_int_falls_back_on_a_bad_value(self, monkeypatch):
        monkeypatch.setenv("SQLSHIELD_TEST_NUMBER", "abc")
        assert env_int("SQLSHIELD_TEST_NUMBER", 7) == 7

    def test_env_list_splits_on_commas(self, monkeypatch):
        monkeypatch.setenv("SQLSHIELD_TEST_LIST", "a, b ,c")
        assert env_list("SQLSHIELD_TEST_LIST") == ["a", "b", "c"]


class TestConfigValue:
    def test_a_mapping_is_read_by_key(self):
        assert config_value({"KEY": "value"}, "KEY") == "value"

    def test_a_class_is_read_by_attribute(self):
        class Sample:
            KEY = "value"

        assert config_value(Sample, "KEY") == "value"

    def test_the_default_is_returned_when_missing(self):
        assert config_value({}, "KEY", "fallback") == "fallback"
        assert config_value(None, "KEY", "fallback") == "fallback"


class TestConfigResolution:
    def test_the_named_config_is_returned(self):
        assert resolve_config("production") is ProductionConfig
        assert resolve_config("testing") is TestingConfig
        assert resolve_config("development") is DevelopmentConfig

    def test_an_unknown_name_falls_back_to_development(self):
        assert resolve_config("nonsense") is DevelopmentConfig

    def test_production_enables_json_logging(self):
        assert (
            evaluate_config({"LOG_JSON": "true"}, "c.ProductionConfig.LOG_JSON") == "True"
        )

    def test_json_logging_can_be_switched_off(self):
        assert (
            evaluate_config({"LOG_JSON": "false"}, "c.ProductionConfig.LOG_JSON")
            == "False"
        )

    def test_production_disables_debug_mode(self):
        assert evaluate_config({}, "c.ProductionConfig.DEBUG") == "False"

    def test_testing_uses_the_in_memory_database(self):
        assert TestingConfig.MONGO_URI.startswith("mongomock://")
        assert TestingConfig.RATELIMIT_ENABLED is False

    def test_the_base_config_exposes_the_settings(self):
        settings = BaseConfig.as_dict()
        assert "MONGO_URI" in settings
        assert "SQLI_BLOCK_THRESHOLD" in settings


class TestEncryptionConfiguration:
    def test_the_legacy_key_is_accepted(self):
        key = base64.urlsafe_b64encode(b"a" * 32).decode()

        class Sample(dict):
            pass

        vault = KeyVault.from_config(Sample(AES_KEYS=[], AES_KEY=key, ACTIVE_KEY_ID="v1"))

        assert vault.is_ready is True

    def test_a_malformed_key_entry_is_rejected(self):
        class Sample(dict):
            pass

        with pytest.raises(CryptoError):
            KeyVault.from_config(Sample(AES_KEYS=["missing-separator"], AES_KEY=""))


class TestEnvironmentFile:
    """The environment file must be loaded before the settings are resolved.

    The configuration classes read the environment when the module is
    imported, so a late ``load_dotenv`` call would silently leave every
    setting empty. The check runs in a subprocess so that the import order is
    reproduced from scratch.
    """

    def test_the_environment_file_is_read_on_import(self, tmp_path):
        (tmp_path / ".env").write_text(
            "SQLSHIELD_RELOAD_CHECK=loaded-from-file\n", encoding="utf-8"
        )

        project_root = Path(__file__).resolve().parent.parent

        environment = {
            **os.environ,
            "PYTHONPATH": str(project_root),
        }
        environment.pop("SQLSHIELD_RELOAD_CHECK", None)

        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "import sqlshield.config as c; print(c.env_str('SQLSHIELD_RELOAD_CHECK'))",
            ],
            cwd=tmp_path,
            env=environment,
            capture_output=True,
            text=True,
            check=False,
        )

        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "loaded-from-file"
