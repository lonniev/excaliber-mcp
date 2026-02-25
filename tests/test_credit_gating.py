"""Tests for Tollbooth credit gating on post_tweet."""

import os
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from excalibur_mcp.vault import _sessions, _dpyc_sessions

_SAMPLE_NPUB = "npub1" + "a" * 58


@pytest.fixture(autouse=True)
def _clean_state():
    """Reset global state between tests."""
    _sessions.clear()
    _dpyc_sessions.clear()
    import excalibur_mcp.server as srv
    srv._vault_instance = None
    srv._settings = None
    srv._commerce_vault = None
    srv._ledger_cache = None
    srv._btcpay_client = None
    yield
    _sessions.clear()
    _dpyc_sessions.clear()
    srv._vault_instance = None
    srv._settings = None
    srv._commerce_vault = None
    srv._ledger_cache = None
    srv._btcpay_client = None


def _mock_user_id(user_id):
    return patch("excalibur_mcp.server._get_current_user_id", return_value=user_id)


# ---------------------------------------------------------------------------
# TOOL_COSTS
# ---------------------------------------------------------------------------


class TestToolCosts:
    def test_post_tweet_is_paid(self):
        from excalibur_mcp.server import TOOL_COSTS
        assert TOOL_COSTS["post_tweet"] > 0

    def test_health_is_free(self):
        from excalibur_mcp.server import TOOL_COSTS
        assert TOOL_COSTS["health"] == 0

    def test_credential_tools_are_free(self):
        from excalibur_mcp.server import TOOL_COSTS
        for tool in ("register_credentials", "activate_session", "session_status"):
            assert TOOL_COSTS[tool] == 0

    def test_credit_tools_are_free(self):
        from excalibur_mcp.server import TOOL_COSTS
        for tool in ("check_balance", "purchase_credits", "check_payment", "account_statement"):
            assert TOOL_COSTS[tool] == 0


# ---------------------------------------------------------------------------
# _debit_or_error
# ---------------------------------------------------------------------------


class TestDebitOrError:
    @pytest.mark.asyncio
    async def test_free_tool_returns_none(self):
        from excalibur_mcp.server import _debit_or_error
        result = await _debit_or_error("health")
        assert result is None

    @pytest.mark.asyncio
    async def test_stdio_mode_still_gates(self):
        """STDIO mode also requires credits — no free pass."""
        from excalibur_mcp.server import _debit_or_error
        # Simulate vault not configured
        with _mock_user_id(None), \
             patch("excalibur_mcp.server._get_ledger_cache",
                   side_effect=ValueError("Commerce vault not configured. Set NEON_DATABASE_URL")):
            result = await _debit_or_error("post_tweet")
        assert result is not None
        assert result["success"] is False
        assert "Credit system unavailable" in result["error"]

    @pytest.mark.asyncio
    async def test_no_dpyc_identity_returns_error(self):
        from excalibur_mcp.server import _debit_or_error
        # Cloud user with no DPYC session
        _dpyc_sessions.clear()
        with _mock_user_id("user-no-dpyc"):
            result = await _debit_or_error("post_tweet")
        assert result is not None
        assert result["success"] is False
        assert "DPYC" in result["error"] or "npub" in result["error"]

    @pytest.mark.asyncio
    async def test_vault_not_configured_blocks(self):
        """If commerce vault isn't configured, paid tools are blocked."""
        from excalibur_mcp.server import _debit_or_error
        _dpyc_sessions["user-1"] = _SAMPLE_NPUB
        with _mock_user_id("user-1"), \
             patch("excalibur_mcp.server._get_ledger_cache",
                   side_effect=ValueError("Commerce vault not configured. Set NEON_DATABASE_URL")):
            result = await _debit_or_error("post_tweet")
        assert result is not None
        assert result["success"] is False
        assert "NEON_DATABASE_URL" in result["error"]

    @pytest.mark.asyncio
    async def test_sufficient_balance_debits(self):
        """With mocked cache.debit(), debit succeeds."""
        from excalibur_mcp.server import _debit_or_error

        mock_cache = MagicMock()
        mock_cache.debit = AsyncMock(return_value=True)

        _dpyc_sessions["user-1"] = _SAMPLE_NPUB
        with _mock_user_id("user-1"), \
             patch("excalibur_mcp.server._get_ledger_cache", return_value=mock_cache):
            result = await _debit_or_error("post_tweet")

        assert result is None
        mock_cache.debit.assert_called_once_with(_SAMPLE_NPUB, "post_tweet", 1)

    @pytest.mark.asyncio
    async def test_insufficient_balance_returns_error(self):
        """With mocked cache.debit() returning False, debit fails."""
        from excalibur_mcp.server import _debit_or_error

        mock_ledger = MagicMock()
        mock_ledger.balance_api_sats = 0

        mock_cache = MagicMock()
        mock_cache.debit = AsyncMock(return_value=False)
        mock_cache.get = AsyncMock(return_value=mock_ledger)

        _dpyc_sessions["user-1"] = _SAMPLE_NPUB
        with _mock_user_id("user-1"), \
             patch("excalibur_mcp.server._get_ledger_cache", return_value=mock_cache):
            result = await _debit_or_error("post_tweet")

        assert result is not None
        assert result["success"] is False
        assert "Insufficient" in result["error"]
        assert "purchase_credits" in result["error"]
        mock_cache.debit.assert_called_once_with(_SAMPLE_NPUB, "post_tweet", 1)


# ---------------------------------------------------------------------------
# _rollback_debit
# ---------------------------------------------------------------------------


class TestRollbackDebit:
    @pytest.mark.asyncio
    async def test_rollback_calls_ledger(self):
        from excalibur_mcp.server import _rollback_debit

        mock_ledger = MagicMock()
        mock_cache = MagicMock()
        mock_cache.get = AsyncMock(return_value=mock_ledger)

        _dpyc_sessions["user-1"] = _SAMPLE_NPUB
        with _mock_user_id("user-1"), \
             patch("excalibur_mcp.server._get_ledger_cache", return_value=mock_cache):
            await _rollback_debit("post_tweet")

        mock_ledger.rollback_debit.assert_called_once_with("post_tweet", 1)

    @pytest.mark.asyncio
    async def test_rollback_noop_for_free_tool(self):
        from excalibur_mcp.server import _rollback_debit
        # Should not raise, even without any mocking
        await _rollback_debit("health")


# ---------------------------------------------------------------------------
# post_tweet with gating
# ---------------------------------------------------------------------------


class TestPostTweetGated:
    @pytest.mark.asyncio
    async def test_stdio_mode_with_credits(self, monkeypatch):
        """In STDIO mode, post_tweet still requires credits via 'stdio:0' identity."""
        from excalibur_mcp.server import post_tweet

        monkeypatch.setenv("X_API_KEY", "k")
        monkeypatch.setenv("X_API_SECRET", "s")
        monkeypatch.setenv("X_ACCESS_TOKEN", "t")
        monkeypatch.setenv("X_ACCESS_TOKEN_SECRET", "ts")

        mock_cache = MagicMock()
        mock_cache.debit = AsyncMock(return_value=True)

        mock_resp = MagicMock()
        mock_resp.status_code = 201
        mock_resp.json.return_value = {"data": {"id": "999", "text": "hi"}}

        with _mock_user_id(None), \
             patch("excalibur_mcp.server._get_ledger_cache", return_value=mock_cache), \
             patch("excalibur_mcp.x_client.httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.post.return_value = mock_resp
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            result = await post_tweet("hi")

        assert result["tweet_id"] == "999"
        mock_cache.debit.assert_called_once()

    @pytest.mark.asyncio
    async def test_insufficient_funds_blocks_tweet(self):
        """Cloud user with zero balance cannot post."""
        from excalibur_mcp.server import post_tweet

        mock_ledger = MagicMock()
        mock_ledger.balance_api_sats = 0

        mock_cache = MagicMock()
        mock_cache.debit = AsyncMock(return_value=False)
        mock_cache.get = AsyncMock(return_value=mock_ledger)

        _dpyc_sessions["user-1"] = _SAMPLE_NPUB
        with _mock_user_id("user-1"), \
             patch("excalibur_mcp.server._get_ledger_cache", return_value=mock_cache):
            result = await post_tweet("blocked tweet")

        assert "Insufficient" in result.get("error", "")
        assert result["success"] is False


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------


class TestSettings:
    def test_loads_defaults(self, monkeypatch, tmp_path):
        from excalibur_mcp.config import Settings
        # Isolate from project .env by pointing to empty dir
        monkeypatch.chdir(tmp_path)
        s = Settings(_env_file=None)
        assert s.seed_balance_sats == 0
        assert s.btcpay_host is None
        assert s.credit_ttl_seconds == 604800

    def test_loads_from_env(self, monkeypatch):
        from excalibur_mcp.config import Settings
        monkeypatch.setenv("BTCPAY_HOST", "https://btcpay.test")
        monkeypatch.setenv("SEED_BALANCE_SATS", "500")
        s = Settings()
        assert s.btcpay_host == "https://btcpay.test"
        assert s.seed_balance_sats == 500
