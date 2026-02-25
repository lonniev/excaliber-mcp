"""Tests for register_credentials, activate_session, and session_status tools."""

import os
import tempfile
from unittest.mock import patch

import pytest

from excaliber_mcp.vault import _sessions, _dpyc_sessions, clear_session

_SAMPLE_NPUB = "npub1" + "a" * 58


@pytest.fixture(autouse=True)
def _clean_state():
    """Reset global state between tests."""
    _sessions.clear()
    _dpyc_sessions.clear()
    # Reset vault singleton
    import excaliber_mcp.server as srv
    srv._vault_instance = None
    yield
    _sessions.clear()
    _dpyc_sessions.clear()
    srv._vault_instance = None


@pytest.fixture
def vault_dir(tmp_path):
    """Set up a temporary vault directory."""
    d = str(tmp_path / "vault")
    with patch.dict(os.environ, {"EXCALIBER_VAULT_DIR": d}):
        yield d


def _mock_user_id(user_id: str):
    """Context manager to mock the Horizon user ID."""
    return patch("excaliber_mcp.server._get_current_user_id", return_value=user_id)


# ---------------------------------------------------------------------------
# register_credentials
# ---------------------------------------------------------------------------


class TestRegisterCredentials:
    @pytest.mark.asyncio
    async def test_success(self, vault_dir):
        from excaliber_mcp.server import register_credentials

        with _mock_user_id("user-42"):
            result = await register_credentials(
                x_api_key="k", x_api_secret="s",
                x_access_token="t", x_access_token_secret="ts",
                passphrase="pass", npub=_SAMPLE_NPUB,
            )

        assert result["success"] is True
        assert result["userId"] == "user-42"
        assert result["dpyc_npub"] == _SAMPLE_NPUB

    @pytest.mark.asyncio
    async def test_activates_session_immediately(self, vault_dir):
        from excaliber_mcp.server import register_credentials
        from excaliber_mcp.vault import get_session

        with _mock_user_id("user-42"):
            await register_credentials(
                x_api_key="my-key", x_api_secret="s",
                x_access_token="t", x_access_token_secret="ts",
                passphrase="pass", npub=_SAMPLE_NPUB,
            )

        session = get_session("user-42")
        assert session is not None
        assert session.x_api_key == "my-key"

    @pytest.mark.asyncio
    async def test_invalid_npub_rejected(self, vault_dir):
        from excaliber_mcp.server import register_credentials

        with _mock_user_id("user-1"):
            result = await register_credentials(
                x_api_key="k", x_api_secret="s",
                x_access_token="t", x_access_token_secret="ts",
                passphrase="pass", npub="not-a-valid-npub",
            )

        assert result["success"] is False
        assert "npub" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_requires_cloud_mode(self):
        from excaliber_mcp.server import register_credentials

        with _mock_user_id(None):
            result = await register_credentials(
                x_api_key="k", x_api_secret="s",
                x_access_token="t", x_access_token_secret="ts",
                passphrase="pass", npub=_SAMPLE_NPUB,
            )

        assert result["success"] is False
        assert "STDIO" in result["error"] or "Horizon" in result["error"]


# ---------------------------------------------------------------------------
# activate_session
# ---------------------------------------------------------------------------


class TestActivateSession:
    @pytest.mark.asyncio
    async def test_success(self, vault_dir):
        from excaliber_mcp.server import activate_session, register_credentials

        # First register
        with _mock_user_id("user-42"):
            await register_credentials(
                x_api_key="k", x_api_secret="s",
                x_access_token="t", x_access_token_secret="ts",
                passphrase="secret", npub=_SAMPLE_NPUB,
            )

        # Clear in-memory session to simulate new session
        clear_session("user-42")

        # Activate
        with _mock_user_id("user-42"):
            result = await activate_session(passphrase="secret")

        assert result["success"] is True
        assert result["dpyc_npub"] == _SAMPLE_NPUB

    @pytest.mark.asyncio
    async def test_wrong_passphrase(self, vault_dir):
        from excaliber_mcp.server import activate_session, register_credentials

        with _mock_user_id("user-42"):
            await register_credentials(
                x_api_key="k", x_api_secret="s",
                x_access_token="t", x_access_token_secret="ts",
                passphrase="correct", npub=_SAMPLE_NPUB,
            )

        clear_session("user-42")

        with _mock_user_id("user-42"):
            result = await activate_session(passphrase="wrong")

        assert result["success"] is False
        assert "passphrase" in result["error"].lower() or "Wrong" in result["error"]

    @pytest.mark.asyncio
    async def test_no_credentials_stored(self, vault_dir):
        from excaliber_mcp.server import activate_session

        with _mock_user_id("nobody"):
            result = await activate_session(passphrase="anything")

        assert result["success"] is False
        assert "No credentials" in result["error"] or "register" in result["error"].lower()

    @pytest.mark.asyncio
    async def test_requires_cloud_mode(self):
        from excaliber_mcp.server import activate_session

        with _mock_user_id(None):
            result = await activate_session(passphrase="pass")

        assert result["success"] is False


# ---------------------------------------------------------------------------
# session_status
# ---------------------------------------------------------------------------


class TestSessionStatus:
    @pytest.mark.asyncio
    async def test_stdio_mode(self):
        from excaliber_mcp.server import session_status

        with _mock_user_id(None):
            result = await session_status()

        assert result["mode"] == "stdio"
        assert result["personal_session"] is False

    @pytest.mark.asyncio
    async def test_cloud_no_session(self):
        from excaliber_mcp.server import session_status

        with _mock_user_id("user-1"):
            result = await session_status()

        assert result["mode"] == "cloud"
        assert result["personal_session"] is False

    @pytest.mark.asyncio
    async def test_cloud_with_session(self, vault_dir):
        from excaliber_mcp.server import register_credentials, session_status

        with _mock_user_id("user-1"):
            await register_credentials(
                x_api_key="k", x_api_secret="s",
                x_access_token="t", x_access_token_secret="ts",
                passphrase="pass", npub=_SAMPLE_NPUB,
            )

        with _mock_user_id("user-1"):
            result = await session_status()

        assert result["mode"] == "cloud"
        assert result["personal_session"] is True
        assert result["dpyc_npub"] == _SAMPLE_NPUB


# ---------------------------------------------------------------------------
# post_tweet with session credentials
# ---------------------------------------------------------------------------


class TestPostTweetSessionFallback:
    @pytest.mark.asyncio
    async def test_uses_session_creds(self, vault_dir):
        """When a session is active, post_tweet should use session credentials."""
        from excaliber_mcp.server import _get_x_credentials, register_credentials

        with _mock_user_id("user-1"):
            await register_credentials(
                x_api_key="session-key", x_api_secret="session-secret",
                x_access_token="session-token", x_access_token_secret="session-ts",
                passphrase="pass", npub=_SAMPLE_NPUB,
            )

        with _mock_user_id("user-1"):
            creds = _get_x_credentials()
            assert creds.api_key == "session-key"

    @pytest.mark.asyncio
    async def test_falls_back_to_env(self, monkeypatch):
        """Without a session, uses env vars."""
        from excaliber_mcp.server import _get_x_credentials

        monkeypatch.setenv("X_API_KEY", "env-key")
        monkeypatch.setenv("X_API_SECRET", "env-secret")
        monkeypatch.setenv("X_ACCESS_TOKEN", "env-token")
        monkeypatch.setenv("X_ACCESS_TOKEN_SECRET", "env-ts")

        with _mock_user_id(None):  # STDIO mode
            creds = _get_x_credentials()
            assert creds.api_key == "env-key"

    @pytest.mark.asyncio
    async def test_cloud_no_session_falls_back_to_env(self, monkeypatch):
        """Cloud user without session also falls back to env vars."""
        from excaliber_mcp.server import _get_x_credentials

        monkeypatch.setenv("X_API_KEY", "env-key")
        monkeypatch.setenv("X_API_SECRET", "env-secret")
        monkeypatch.setenv("X_ACCESS_TOKEN", "env-token")
        monkeypatch.setenv("X_ACCESS_TOKEN_SECRET", "env-ts")

        with _mock_user_id("user-no-session"):
            creds = _get_x_credentials()
            assert creds.api_key == "env-key"
