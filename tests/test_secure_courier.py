"""Tests for Secure Courier tools (request_credential_channel, receive_credentials, forget_credentials)."""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from excalibur_mcp.vault import _sessions, _dpyc_sessions, clear_session, FileCredentialVault

_SAMPLE_NPUB = "npub1" + "a" * 58
_SAMPLE_NSEC = None  # Generated in fixtures


@pytest.fixture(autouse=True)
def _clean_state():
    """Reset global state between tests."""
    _sessions.clear()
    _dpyc_sessions.clear()
    import excalibur_mcp.server as srv
    srv._vault_instance = None
    srv._courier_exchange = None
    yield
    _sessions.clear()
    _dpyc_sessions.clear()
    srv._vault_instance = None
    srv._courier_exchange = None


@pytest.fixture
def vault_dir(tmp_path):
    """Set up a temporary vault directory."""
    d = str(tmp_path / "vault")
    with patch.dict(os.environ, {"EXCALIBUR_VAULT_DIR": d}):
        yield d


@pytest.fixture
def operator_nsec():
    """Generate a fresh operator nsec for testing."""
    from pynostr.key import PrivateKey
    return PrivateKey().nsec


def _mock_user_id(user_id):
    return patch("excalibur_mcp.server._get_current_user_id", return_value=user_id)


def _mock_settings(**overrides):
    """Create a mock Settings with Secure Courier env vars."""
    defaults = {
        "btcpay_host": None,
        "btcpay_store_id": None,
        "btcpay_api_key": None,
        "btcpay_tier_config": None,
        "btcpay_user_tiers": None,
        "seed_balance_sats": 0,
        "tollbooth_royalty_address": None,
        "tollbooth_royalty_percent": 0.02,
        "tollbooth_royalty_min_sats": 10,
        "dpyc_operator_npub": None,
        "dpyc_authority_npub": None,
        "credit_ttl_seconds": None,
        "neon_database_url": None,
        "tollbooth_ots_enabled": None,
        "tollbooth_ots_calendars": None,
        "excalibur_vault_dir": None,
        "tollbooth_nostr_operator_nsec": None,
        "tollbooth_nostr_relays": None,
    }
    defaults.update(overrides)
    settings = MagicMock(**defaults)
    return settings


class TestRequestCredentialChannel:
    @pytest.mark.asyncio
    async def test_returns_npub_and_instructions(self, vault_dir, operator_nsec):
        from excalibur_mcp.server import request_credential_channel
        import excalibur_mcp.server as srv

        settings = _mock_settings(
            tollbooth_nostr_operator_nsec=operator_nsec,
            excalibur_vault_dir=vault_dir,
        )

        with patch.object(srv, "get_settings", return_value=settings), \
             patch.object(srv, "_start_subscription_noop", create=True):
            # Mock the relay subscription to avoid real WebSocket I/O
            result = await request_credential_channel("x")

        assert result["success"] is True
        assert result["npub"].startswith("npub1")
        assert "access_token" in result["instructions"]
        assert result["service"] == "x"

    @pytest.mark.asyncio
    async def test_not_configured_returns_error(self):
        from excalibur_mcp.server import request_credential_channel
        import excalibur_mcp.server as srv

        settings = _mock_settings(tollbooth_nostr_operator_nsec=None)

        with patch.object(srv, "get_settings", return_value=settings):
            result = await request_credential_channel("x")

        assert result["success"] is False
        assert "not configured" in result["error"].lower()


class TestReceiveCredentials:
    @pytest.mark.asyncio
    async def test_vault_hit_activates_session(self, vault_dir, operator_nsec):
        """When vault has cached credentials, session is activated."""
        from excalibur_mcp.server import receive_credentials
        from excalibur_mcp.vault import get_session
        import excalibur_mcp.server as srv

        settings = _mock_settings(
            tollbooth_nostr_operator_nsec=operator_nsec,
            excalibur_vault_dir=vault_dir,
        )

        mock_result = {
            "success": True,
            "service": "x",
            "fields_received": 2,
            "sensitive_fields": 2,
            "encryption": "vault",
            "credentials": {
                "access_token": "t",
                "access_token_secret": "ts",
            },
            "message": "Credentials restored from vault.",
        }

        with patch.object(srv, "get_settings", return_value=settings), \
             patch.dict(os.environ, {"X_API_KEY": "op-key", "X_API_SECRET": "op-secret"}), \
             _mock_user_id("user-42"):
            # Initialize exchange, then mock receive
            exchange = srv._get_courier_exchange()
            with patch.object(exchange, "receive", new_callable=AsyncMock, return_value=mock_result):
                result = await receive_credentials(_SAMPLE_NPUB)

        assert result["success"] is True
        assert result["session_activated"] is True
        # Credentials should NOT be in the result
        assert "credentials" not in result

        session = get_session("user-42")
        assert session is not None
        # api_key comes from operator ENV, access_token from patron's pouch
        assert session.x_api_key == "op-key"
        assert session.x_api_secret == "op-secret"
        assert session.x_access_token == "t"
        assert session.x_access_token_secret == "ts"

    @pytest.mark.asyncio
    async def test_credentials_never_echoed(self, vault_dir, operator_nsec):
        """Credential values are never returned in the tool result."""
        from excalibur_mcp.server import receive_credentials
        import excalibur_mcp.server as srv

        settings = _mock_settings(
            tollbooth_nostr_operator_nsec=operator_nsec,
            excalibur_vault_dir=vault_dir,
        )

        mock_result = {
            "success": True,
            "service": "x",
            "fields_received": 2,
            "sensitive_fields": 2,
            "encryption": "nip04",
            "credentials": {
                "access_token": "secret-token",
                "access_token_secret": "secret-ts",
            },
            "message": "Credentials received.",
        }

        with patch.object(srv, "get_settings", return_value=settings), \
             patch.dict(os.environ, {"X_API_KEY": "op-key", "X_API_SECRET": "op-secret"}), \
             _mock_user_id("user-1"):
            exchange = srv._get_courier_exchange()
            with patch.object(exchange, "receive", new_callable=AsyncMock, return_value=mock_result):
                result = await receive_credentials(_SAMPLE_NPUB)

        assert "credentials" not in result
        assert "secret-token" not in str(result)


class TestForgetCredentials:
    @pytest.mark.asyncio
    async def test_forget_returns_result(self, vault_dir, operator_nsec):
        from excalibur_mcp.server import forget_credentials
        import excalibur_mcp.server as srv

        settings = _mock_settings(
            tollbooth_nostr_operator_nsec=operator_nsec,
            excalibur_vault_dir=vault_dir,
        )

        with patch.object(srv, "get_settings", return_value=settings):
            result = await forget_credentials(_SAMPLE_NPUB)

        assert result["success"] is True
        assert result["deleted"] is False  # Nothing stored yet

    @pytest.mark.asyncio
    async def test_forget_not_configured(self):
        from excalibur_mcp.server import forget_credentials
        import excalibur_mcp.server as srv

        settings = _mock_settings(tollbooth_nostr_operator_nsec=None)

        with patch.object(srv, "get_settings", return_value=settings):
            result = await forget_credentials(_SAMPLE_NPUB)

        assert result["success"] is False


class TestFileCredentialVault:
    @pytest.mark.asyncio
    async def test_store_fetch_delete(self, tmp_path):
        vault = FileCredentialVault(str(tmp_path / "cv"))

        await vault.store_credentials("x", _SAMPLE_NPUB, "encrypted-blob")
        assert await vault.fetch_credentials("x", _SAMPLE_NPUB) == "encrypted-blob"

        deleted = await vault.delete_credentials("x", _SAMPLE_NPUB)
        assert deleted is True
        assert await vault.fetch_credentials("x", _SAMPLE_NPUB) is None

    @pytest.mark.asyncio
    async def test_fetch_nonexistent(self, tmp_path):
        vault = FileCredentialVault(str(tmp_path / "cv"))
        assert await vault.fetch_credentials("x", "npub1nobody") is None

    @pytest.mark.asyncio
    async def test_delete_nonexistent(self, tmp_path):
        vault = FileCredentialVault(str(tmp_path / "cv"))
        assert await vault.delete_credentials("x", "npub1nobody") is False
