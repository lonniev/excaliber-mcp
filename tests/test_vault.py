"""Tests for the multi-tenant credential vault."""

import json
import os
import tempfile
import time
from unittest.mock import patch

import pytest

from excalibur_mcp.vault import (
    CredentialNotFoundError,
    DecryptionError,
    FileVault,
    UserSession,
    SESSION_TTL_SECONDS,
    clear_session,
    decrypt_credentials,
    derive_key,
    encrypt_credentials,
    get_dpyc_npub,
    get_session,
    set_session,
    _sessions,
    _dpyc_sessions,
)


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------


class TestDeriveKey:
    def test_deterministic(self):
        """Same passphrase + salt → same key."""
        salt = b"0123456789abcdef"
        k1 = derive_key("my-pass", salt)
        k2 = derive_key("my-pass", salt)
        assert k1 == k2

    def test_different_salt_different_key(self):
        k1 = derive_key("pass", b"salt_a__________")
        k2 = derive_key("pass", b"salt_b__________")
        assert k1 != k2

    def test_different_passphrase_different_key(self):
        salt = b"same_salt_______"
        k1 = derive_key("pass-a", salt)
        k2 = derive_key("pass-b", salt)
        assert k1 != k2

    def test_key_is_bytes(self):
        key = derive_key("test", b"0123456789abcdef")
        assert isinstance(key, bytes)
        assert len(key) == 44  # base64-encoded 32 bytes


# ---------------------------------------------------------------------------
# Encrypt / decrypt round-trip
# ---------------------------------------------------------------------------

_SAMPLE_NPUB = "npub1" + "a" * 58  # 63 chars total


class TestEncryptDecrypt:
    def test_round_trip(self):
        blob = encrypt_credentials(
            "api-key", "api-secret", "token", "token-secret",
            "my-passphrase", npub=_SAMPLE_NPUB,
        )
        creds = decrypt_credentials(blob, "my-passphrase")
        assert creds["x_api_key"] == "api-key"
        assert creds["x_api_secret"] == "api-secret"
        assert creds["x_access_token"] == "token"
        assert creds["x_access_token_secret"] == "token-secret"
        assert creds["npub"] == _SAMPLE_NPUB

    def test_round_trip_no_npub(self):
        blob = encrypt_credentials(
            "k", "s", "t", "ts", "pass",
        )
        creds = decrypt_credentials(blob, "pass")
        assert creds["x_api_key"] == "k"
        assert "npub" not in creds

    def test_wrong_passphrase_raises(self):
        blob = encrypt_credentials("k", "s", "t", "ts", "correct")
        with pytest.raises(DecryptionError, match="Wrong passphrase"):
            decrypt_credentials(blob, "wrong")

    def test_corrupted_json_raises(self):
        with pytest.raises(DecryptionError, match="corrupted"):
            decrypt_credentials("not json at all", "pass")

    def test_missing_fields_raises(self):
        with pytest.raises(DecryptionError, match="missing fields"):
            decrypt_credentials('{"v": 1}', "pass")

    def test_blob_is_valid_json(self):
        blob = encrypt_credentials("k", "s", "t", "ts", "pass")
        envelope = json.loads(blob)
        assert envelope["v"] == 1
        assert "salt" in envelope
        assert "data" in envelope

    def test_different_passphrases_different_blobs(self):
        b1 = encrypt_credentials("k", "s", "t", "ts", "pass-a")
        b2 = encrypt_credentials("k", "s", "t", "ts", "pass-b")
        assert b1 != b2

    def test_same_passphrase_different_salt(self):
        """Each encryption generates a unique random salt."""
        b1 = encrypt_credentials("k", "s", "t", "ts", "same")
        b2 = encrypt_credentials("k", "s", "t", "ts", "same")
        e1 = json.loads(b1)
        e2 = json.loads(b2)
        assert e1["salt"] != e2["salt"]


# ---------------------------------------------------------------------------
# Session management
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _clean_sessions():
    """Clear global session state before each test."""
    _sessions.clear()
    _dpyc_sessions.clear()
    yield
    _sessions.clear()
    _dpyc_sessions.clear()


class TestSessions:
    def test_set_and_get(self):
        s = set_session("user-1", "k", "s", "t", "ts", npub=_SAMPLE_NPUB)
        assert isinstance(s, UserSession)
        got = get_session("user-1")
        assert got is s
        assert got.x_api_key == "k"

    def test_get_absent_returns_none(self):
        assert get_session("nobody") is None

    def test_clear(self):
        set_session("u", "k", "s", "t", "ts")
        clear_session("u")
        assert get_session("u") is None

    def test_expiration(self):
        s = set_session("u", "k", "s", "t", "ts")
        # Force the session to appear expired
        s.created_at = time.time() - SESSION_TTL_SECONDS - 1
        assert s.is_expired
        assert get_session("u") is None  # auto-evicted

    def test_not_expired(self):
        s = set_session("u", "k", "s", "t", "ts")
        assert not s.is_expired
        assert get_session("u") is s

    def test_dpyc_npub_tracking(self):
        set_session("u", "k", "s", "t", "ts", npub=_SAMPLE_NPUB)
        assert get_dpyc_npub("u") == _SAMPLE_NPUB

    def test_dpyc_npub_none_without_npub(self):
        set_session("u", "k", "s", "t", "ts")
        assert get_dpyc_npub("u") is None

    def test_clear_removes_dpyc(self):
        set_session("u", "k", "s", "t", "ts", npub=_SAMPLE_NPUB)
        clear_session("u")
        assert get_dpyc_npub("u") is None

    def test_repr_redacts_secrets(self):
        s = set_session("u", "secret-key", "s", "t", "ts")
        r = repr(s)
        assert "secret-key" not in r
        assert "<redacted>" in r

    def test_age_seconds(self):
        s = set_session("u", "k", "s", "t", "ts")
        assert s.age_seconds >= 0
        assert s.age_seconds < 5  # just created

    def test_replace_session(self):
        set_session("u", "old-k", "s", "t", "ts")
        set_session("u", "new-k", "s", "t", "ts")
        s = get_session("u")
        assert s.x_api_key == "new-k"


# ---------------------------------------------------------------------------
# FileVault
# ---------------------------------------------------------------------------


class TestFileVault:
    @pytest.fixture
    def vault(self, tmp_path):
        return FileVault(str(tmp_path / "vault"))

    @pytest.mark.asyncio
    async def test_store_and_fetch(self, vault):
        blob = '{"v":1,"salt":"abc","data":"xyz"}'
        await vault.store("user-1", blob)
        fetched = await vault.fetch("user-1")
        assert fetched == blob

    @pytest.mark.asyncio
    async def test_fetch_not_found(self, vault):
        with pytest.raises(CredentialNotFoundError):
            await vault.fetch("nobody")

    @pytest.mark.asyncio
    async def test_overwrite(self, vault):
        await vault.store("u", "blob-1")
        await vault.store("u", "blob-2")
        assert await vault.fetch("u") == "blob-2"

    @pytest.mark.asyncio
    async def test_multiple_users(self, vault):
        await vault.store("alice", "a-blob")
        await vault.store("bob", "b-blob")
        assert await vault.fetch("alice") == "a-blob"
        assert await vault.fetch("bob") == "b-blob"

    @pytest.mark.asyncio
    async def test_creates_directory(self, tmp_path):
        vault_dir = str(tmp_path / "deep" / "nested" / "vault")
        vault = FileVault(vault_dir)
        await vault.store("u", "data")
        assert os.path.isdir(vault_dir)


# ---------------------------------------------------------------------------
# Full integration: encrypt → store → fetch → decrypt
# ---------------------------------------------------------------------------


class TestVaultIntegration:
    @pytest.mark.asyncio
    async def test_full_flow(self, tmp_path):
        vault = FileVault(str(tmp_path / "vault"))

        # Register
        blob = encrypt_credentials(
            "real-key", "real-secret", "real-token", "real-ts",
            "hunter2", npub=_SAMPLE_NPUB,
        )
        await vault.store("horizon-user-42", blob)

        # Activate (new session)
        fetched = await vault.fetch("horizon-user-42")
        creds = decrypt_credentials(fetched, "hunter2")

        assert creds["x_api_key"] == "real-key"
        assert creds["x_api_secret"] == "real-secret"
        assert creds["x_access_token"] == "real-token"
        assert creds["x_access_token_secret"] == "real-ts"
        assert creds["npub"] == _SAMPLE_NPUB

    @pytest.mark.asyncio
    async def test_wrong_passphrase_on_fetch(self, tmp_path):
        vault = FileVault(str(tmp_path / "vault"))
        blob = encrypt_credentials("k", "s", "t", "ts", "correct-pass")
        await vault.store("u", blob)

        fetched = await vault.fetch("u")
        with pytest.raises(DecryptionError):
            decrypt_credentials(fetched, "wrong-pass")
