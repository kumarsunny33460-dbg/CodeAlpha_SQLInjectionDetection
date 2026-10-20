"""Tests for the cryptographic services."""

from __future__ import annotations

import base64

import pytest

from sqlshield.security.crypto import (
    CryptoError,
    KeyVault,
    constant_time_equals,
    decode_key,
    generate_key,
    hash_password,
    verify_password,
)


def _key(seed: bytes) -> str:
    return base64.urlsafe_b64encode(seed).decode()


@pytest.fixture()
def vault():
    return KeyVault(
        keys={
            "v1": decode_key(_key(b"a" * 32)),
            "v2": decode_key(_key(b"b" * 32)),
        },
        active_key_id="v1",
    )


class TestKeyVault:
    def test_encrypt_and_decrypt_round_trip(self, vault):
        token = vault.encrypt("sunny@example.com")
        assert vault.decrypt(token) == "sunny@example.com"

    def test_ciphertext_is_not_the_plaintext(self, vault):
        token = vault.encrypt("sunny@example.com")
        assert "sunny@example.com" not in token

    def test_envelope_carries_the_key_id(self, vault):
        assert vault.encrypt("value").startswith("enc:v1:")

    def test_each_encryption_uses_a_fresh_nonce(self, vault):
        assert vault.encrypt("value") != vault.encrypt("value")

    def test_additional_data_binds_the_ciphertext(self, vault):
        token = vault.encrypt("value", aad=b"email")
        assert vault.decrypt(token, aad=b"email") == "value"
        with pytest.raises(CryptoError):
            vault.decrypt(token, aad=b"name")

    def test_rotation_keeps_old_ciphertext_readable(self, vault):
        old_token = vault.encrypt("value")

        vault.active_key_id = "v2"
        new_token = vault.encrypt("value")

        assert new_token.startswith("enc:v2:")
        assert vault.decrypt(old_token) == "value"
        assert vault.decrypt(new_token) == "value"

    def test_reencrypt_uses_the_active_key(self, vault):
        old_token = vault.encrypt("value")
        vault.active_key_id = "v2"

        rotated = vault.reencrypt(old_token)
        assert rotated.startswith("enc:v2:")
        assert vault.decrypt(rotated) == "value"

    def test_decrypting_with_the_wrong_key_fails(self, vault):
        token = vault.encrypt("value", aad=b"email")
        vault.keys["v1"] = decode_key(_key(b"c" * 32))

        with pytest.raises(CryptoError):
            vault.decrypt(token, aad=b"email")

    def test_empty_vault_is_not_ready(self):
        empty = KeyVault()
        assert empty.is_ready is False
        with pytest.raises(CryptoError):
            empty.encrypt("value")

    def test_from_config_reads_multiple_keys(self):
        class FakeConfig(dict):
            pass

        config = FakeConfig(
            AES_KEYS=[f"v1:{_key(b'a' * 32)}", f"v2:{_key(b'b' * 32)}"],
            ACTIVE_KEY_ID="v2",
            AES_KEY="",
        )

        vault = KeyVault.from_config(config)
        assert vault.key_ids == ("v1", "v2")
        assert vault.active_key_id == "v2"

    def test_from_config_falls_back_to_the_legacy_key(self):
        class FakeConfig(dict):
            pass

        config = FakeConfig(AES_KEYS=[], AES_KEY=_key(b"d" * 32), ACTIVE_KEY_ID="v1")

        vault = KeyVault.from_config(config)
        assert vault.is_ready is True
        assert vault.active_key_id == "v1"

    def test_invalid_key_length_is_rejected(self):
        with pytest.raises(CryptoError):
            decode_key(base64.urlsafe_b64encode(b"short").decode())

    def test_generated_keys_are_usable(self):
        vault = KeyVault(keys={"v1": decode_key(generate_key())})
        assert vault.decrypt(vault.encrypt("value")) == "value"


class TestPasswordHashing:
    def test_hash_is_not_the_password(self):
        hashed = hash_password("Sup3rSecret!")
        assert "Sup3rSecret!" not in hashed

    def test_hash_has_a_versioned_format(self):
        assert hash_password("Sup3rSecret!").startswith("pbkdf2_sha256$")

    def test_verify_accepts_the_right_password(self):
        hashed = hash_password("Sup3rSecret!")
        assert verify_password("Sup3rSecret!", hashed) is True

    def test_verify_rejects_the_wrong_password(self):
        hashed = hash_password("Sup3rSecret!")
        assert verify_password("wrong", hashed) is False

    def test_salt_makes_the_hashes_unique(self):
        assert hash_password("Sup3rSecret!") != hash_password("Sup3rSecret!")

    def test_malformed_hash_is_rejected(self):
        assert verify_password("Sup3rSecret!", "not-a-hash") is False
        assert verify_password("Sup3rSecret!", "") is False

    def test_a_different_work_factor_still_verifies(self):
        hashed = hash_password("Sup3rSecret!", iterations=1000)
        assert verify_password("Sup3rSecret!", hashed) is True


class TestConstantTimeComparison:
    def test_equal_values_match(self):
        assert constant_time_equals("secret", "secret") is True

    def test_different_values_do_not_match(self):
        assert constant_time_equals("secret", "secrez") is False

    def test_none_is_handled(self):
        assert constant_time_equals(None, "secret") is False
        assert constant_time_equals("secret", None) is False
