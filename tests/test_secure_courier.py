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
    srv._courier_service = None
    yield
    _sessions.clear()
    _dpyc_sessions.clear()
    srv._vault_instance = None
    srv._courier_service = None


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
    async def test_sends_welcome_dm_with_recipient_npub(self, vault_dir, operator_nsec):
        from excalibur_mcp.server import request_credential_channel
        import excalibur_mcp.server as srv

        settings = _mock_settings(
            tollbooth_nostr_operator_nsec=operator_nsec,
            excalibur_vault_dir=vault_dir,
        )

        with patch.object(srv, "get_settings", return_value=settings):
            courier = srv._get_courier_service()
            exchange = courier.exchange
            with patch.object(exchange, "_start_subscription"), \
                 patch.object(exchange, "send_dm") as mock_send:
                result = await request_credential_channel("x", recipient_npub=_SAMPLE_NPUB)

        assert result["success"] is True
        assert result["welcome_dm_sent"] is True
        mock_send.assert_called_once()

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

        # Mock result from the underlying exchange (includes credentials)
        exchange_result = {
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
            # Initialize the service, then mock the underlying exchange
            courier = srv._get_courier_service()
            with patch.object(courier.exchange, "receive", new_callable=AsyncMock, return_value=exchange_result):
                result = await receive_credentials(_SAMPLE_NPUB)

        assert result["success"] is True
        assert result["session_activated"] is True
        # Credentials should NOT be in the result (stripped by SecureCourierService)
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

        exchange_result = {
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
            courier = srv._get_courier_service()
            with patch.object(courier.exchange, "receive", new_callable=AsyncMock, return_value=exchange_result):
                result = await receive_credentials(_SAMPLE_NPUB)

        assert "credentials" not in result
        assert "secret-token" not in str(result)


    @pytest.mark.asyncio
    async def test_dpyc_identity_established_on_receive(self, vault_dir, operator_nsec):
        """After successful receive, DPYC identity is established via sender_npub."""
        from excalibur_mcp.server import receive_credentials
        from excalibur_mcp.vault import get_dpyc_npub
        import excalibur_mcp.server as srv

        settings = _mock_settings(
            tollbooth_nostr_operator_nsec=operator_nsec,
            excalibur_vault_dir=vault_dir,
        )

        exchange_result = {
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
             _mock_user_id("user-dpyc"):
            courier = srv._get_courier_service()
            with patch.object(courier.exchange, "receive", new_callable=AsyncMock, return_value=exchange_result):
                result = await receive_credentials(_SAMPLE_NPUB)

        assert result["dpyc_npub"] == _SAMPLE_NPUB
        assert get_dpyc_npub("user-dpyc") == _SAMPLE_NPUB

    @pytest.mark.asyncio
    async def test_seed_balance_applied_on_first_receive(self, vault_dir, operator_nsec):
        """First credential receive seeds the starter balance."""
        from excalibur_mcp.server import receive_credentials
        import excalibur_mcp.server as srv

        settings = _mock_settings(
            tollbooth_nostr_operator_nsec=operator_nsec,
            excalibur_vault_dir=vault_dir,
            seed_balance_sats=100,
        )

        exchange_result = {
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
             _mock_user_id("user-seed"), \
             patch.object(srv, "_seed_balance", new_callable=AsyncMock, return_value=True) as mock_seed:
            courier = srv._get_courier_service()
            with patch.object(courier.exchange, "receive", new_callable=AsyncMock, return_value=exchange_result):
                result = await receive_credentials(_SAMPLE_NPUB)

        mock_seed.assert_called_once_with(_SAMPLE_NPUB)
        assert result["seed_applied"] is True
        assert result["seed_balance_api_sats"] == 100

    @pytest.mark.asyncio
    async def test_seed_balance_idempotent_on_repeat_receive(self, vault_dir, operator_nsec):
        """Repeat credential receive does NOT re-seed the balance."""
        from excalibur_mcp.server import receive_credentials
        import excalibur_mcp.server as srv

        settings = _mock_settings(
            tollbooth_nostr_operator_nsec=operator_nsec,
            excalibur_vault_dir=vault_dir,
            seed_balance_sats=100,
        )

        exchange_result = {
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
             _mock_user_id("user-repeat"), \
             patch.object(srv, "_seed_balance", new_callable=AsyncMock, return_value=False):
            courier = srv._get_courier_service()
            with patch.object(courier.exchange, "receive", new_callable=AsyncMock, return_value=exchange_result):
                result = await receive_credentials(_SAMPLE_NPUB)

        assert "seed_applied" not in result


class TestReceiveCredentialsPassphraseBridge:
    """Tests for the optional passphrase parameter on receive_credentials."""

    def _exchange_result(self):
        return {
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

    @pytest.mark.asyncio
    async def test_passphrase_stores_in_file_vault(self, vault_dir, operator_nsec):
        """When passphrase is provided, credentials are stored in FileVault."""
        from excalibur_mcp.server import receive_credentials
        import excalibur_mcp.server as srv

        settings = _mock_settings(
            tollbooth_nostr_operator_nsec=operator_nsec,
            excalibur_vault_dir=vault_dir,
        )

        with patch.object(srv, "get_settings", return_value=settings), \
             patch.dict(os.environ, {"X_API_KEY": "op-key", "X_API_SECRET": "op-secret"}), \
             _mock_user_id("user-bridge"):
            courier = srv._get_courier_service()
            with patch.object(courier.exchange, "receive", new_callable=AsyncMock, return_value=self._exchange_result()):
                result = await receive_credentials(_SAMPLE_NPUB, passphrase="Open Sesame")

        assert result["success"] is True
        assert result["vault_stored"] is True
        assert "passphrase vault" in result["message"]

    @pytest.mark.asyncio
    async def test_passphrase_enables_activate_session(self, vault_dir, operator_nsec):
        """After receive_credentials with passphrase, activate_session works."""
        from excalibur_mcp.server import receive_credentials, activate_session
        from excalibur_mcp.vault import get_session
        import excalibur_mcp.server as srv

        settings = _mock_settings(
            tollbooth_nostr_operator_nsec=operator_nsec,
            excalibur_vault_dir=vault_dir,
        )

        # Step 1: receive with passphrase
        with patch.object(srv, "get_settings", return_value=settings), \
             patch.dict(os.environ, {"X_API_KEY": "op-key", "X_API_SECRET": "op-secret"}), \
             _mock_user_id("user-bridge"):
            courier = srv._get_courier_service()
            with patch.object(courier.exchange, "receive", new_callable=AsyncMock, return_value=self._exchange_result()):
                await receive_credentials(_SAMPLE_NPUB, passphrase="Open Sesame")

        # Step 2: clear in-memory session (simulates new process)
        clear_session("user-bridge")
        assert get_session("user-bridge") is None

        # Step 3: activate_session with same passphrase
        with _mock_user_id("user-bridge"):
            result = await activate_session(passphrase="Open Sesame")

        assert result["success"] is True
        assert result["dpyc_npub"] == _SAMPLE_NPUB

        session = get_session("user-bridge")
        assert session is not None
        assert session.x_api_key == "op-key"
        assert session.x_access_token == "t"

    @pytest.mark.asyncio
    async def test_no_passphrase_skips_vault_store(self, vault_dir, operator_nsec):
        """Without passphrase, no FileVault write occurs."""
        from excalibur_mcp.server import receive_credentials
        import excalibur_mcp.server as srv

        settings = _mock_settings(
            tollbooth_nostr_operator_nsec=operator_nsec,
            excalibur_vault_dir=vault_dir,
        )

        with patch.object(srv, "get_settings", return_value=settings), \
             patch.dict(os.environ, {"X_API_KEY": "op-key", "X_API_SECRET": "op-secret"}), \
             _mock_user_id("user-nopass"):
            courier = srv._get_courier_service()
            with patch.object(courier.exchange, "receive", new_callable=AsyncMock, return_value=self._exchange_result()):
                result = await receive_credentials(_SAMPLE_NPUB)

        assert result["success"] is True
        assert "vault_stored" not in result

    @pytest.mark.asyncio
    async def test_vault_failure_warns_but_succeeds(self, vault_dir, operator_nsec):
        """If vault storage fails, courier result still succeeds with a warning."""
        from excalibur_mcp.server import receive_credentials
        import excalibur_mcp.server as srv

        settings = _mock_settings(
            tollbooth_nostr_operator_nsec=operator_nsec,
            excalibur_vault_dir=vault_dir,
        )

        with patch.object(srv, "get_settings", return_value=settings), \
             patch.dict(os.environ, {"X_API_KEY": "op-key", "X_API_SECRET": "op-secret"}), \
             _mock_user_id("user-fail"):
            courier = srv._get_courier_service()
            with patch.object(courier.exchange, "receive", new_callable=AsyncMock, return_value=self._exchange_result()), \
                 patch.object(srv, "_get_vault", side_effect=Exception("vault boom")):
                result = await receive_credentials(_SAMPLE_NPUB, passphrase="secret")

        assert result["success"] is True
        assert "vault_warning" in result
        assert "vault boom" in result["vault_warning"]


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
            # _get_courier_service() creates the service with a real FileCredentialVault
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
