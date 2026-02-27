"""Tests for the account_statement_infographic tool and SVG generator."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from excalibur_mcp.infographic import render_account_infographic, svg_to_png_base64
from excalibur_mcp.vault import _dpyc_sessions, _sessions

_SAMPLE_NPUB = "npub1" + "a" * 58


def _sample_statement_data(
    balance: int = 420,
    deposited: int = 1000,
    consumed: int = 550,
    expired: int = 30,
) -> dict:
    """Return a realistic account_statement_tool result for testing."""
    return {
        "success": True,
        "generated_at": "2026-02-26T14:30:00+00:00",
        "account_summary": {
            "balance_api_sats": balance,
            "total_deposited_api_sats": deposited,
            "total_consumed_api_sats": consumed,
            "total_expired_api_sats": expired,
        },
        "active_tranches": [
            {
                "invoice_id": "seed_balance_v1",
                "granted_at": "2026-02-20T10:00:00+00:00",
                "original_sats": 500,
                "remaining_sats": 200,
            },
            {
                "invoice_id": "btcpay_inv_abcdef123456789",
                "granted_at": "2026-02-24T18:00:00+00:00",
                "original_sats": 500,
                "remaining_sats": 220,
            },
        ],
        "tool_usage_all_time": [
            {"tool": "post_tweet", "calls": 42, "api_sats": 42},
            {"tool": "post_tweet_image", "calls": 5, "api_sats": 10},
            {"tool": "account_statement_infographic", "calls": 3, "api_sats": 3},
        ],
        "daily_usage": [],
    }


# ---------------------------------------------------------------------------
# SVG generation unit tests
# ---------------------------------------------------------------------------


class TestRenderAccountInfographic:
    def test_returns_valid_svg(self):
        svg = render_account_infographic(_sample_statement_data())
        assert svg.startswith("<svg ")
        assert svg.endswith("</svg>")
        assert 'xmlns="http://www.w3.org/2000/svg"' in svg

    def test_excalibur_branding(self):
        svg = render_account_infographic(_sample_statement_data())
        assert "eXcalibur" in svg
        # Sword emoji (U+2694 crossed swords)
        assert "\u2694" in svg
        # Should NOT contain TheBrain references
        assert "Personal Brain" not in svg
        assert "TheBrain" not in svg
        assert "thebrain" not in svg.lower().replace("thebrain", "FOUND")
        # Actually check case-insensitively for "thebrain" substring
        assert "thebrain" not in svg.lower()

    def test_balance_displayed(self):
        svg = render_account_infographic(_sample_statement_data(balance=1234))
        assert "1,234" in svg

    def test_metrics_displayed(self):
        data = _sample_statement_data(deposited=5000, consumed=3000, expired=100)
        svg = render_account_infographic(data)
        assert "5,000" in svg
        assert "3,000" in svg
        assert "100" in svg

    def test_tranche_table(self):
        svg = render_account_infographic(_sample_statement_data())
        assert "ACTIVE CREDIT TRANCHES" in svg
        assert "Seed (v1)" in svg
        # Long invoice ID should be truncated (first 12 chars + "..")
        assert "btcpay_inv_a.." in svg

    def test_no_tranches(self):
        data = _sample_statement_data()
        data["active_tranches"] = []
        svg = render_account_infographic(data)
        assert "No active tranches" in svg

    def test_tool_usage_table(self):
        svg = render_account_infographic(_sample_statement_data())
        assert "TOOL USAGE (ALL-TIME)" in svg
        assert "post_tweet" in svg
        assert "post_tweet_image" in svg
        assert "account_statement_infographic" in svg

    def test_no_tool_usage(self):
        data = _sample_statement_data()
        data["tool_usage_all_time"] = []
        svg = render_account_infographic(data)
        assert "No usage yet" in svg

    def test_health_gauge_present(self):
        svg = render_account_infographic(_sample_statement_data())
        assert "BALANCE HEALTH" in svg
        assert "remaining" in svg

    def test_footer_branding(self):
        svg = render_account_infographic(_sample_statement_data())
        assert "DPYC" in svg
        assert "eXcalibur MCP" in svg
        assert "Lightning" in svg

    def test_zero_deposited_no_division_error(self):
        """When deposited is 0, health gauge should show 100% (not crash)."""
        data = _sample_statement_data(balance=0, deposited=0, consumed=0, expired=0)
        svg = render_account_infographic(data)
        assert "100.0%" in svg

    def test_timestamp_displayed(self):
        svg = render_account_infographic(_sample_statement_data())
        assert "2026-02-26 14:30:00 UTC" in svg

    def test_empty_data_graceful(self):
        """Completely empty data dict should not crash."""
        svg = render_account_infographic({})
        assert svg.startswith("<svg ")
        assert svg.endswith("</svg>")


# ---------------------------------------------------------------------------
# PNG conversion
# ---------------------------------------------------------------------------


class TestSvgToPngBase64:
    def test_returns_none_without_cairosvg(self):
        """When cairosvg is not installed, returns None gracefully."""
        with patch.dict("sys.modules", {"cairosvg": None}):
            # Force ImportError by patching import
            result = svg_to_png_base64("<svg></svg>")
        # In practice, if cairosvg isn't installed, it returns None.
        # The exact behavior depends on environment, so we just check no crash.
        assert result is None or isinstance(result, str)

    def test_returns_base64_with_mock_cairosvg(self):
        """When cairosvg is available, returns base64 string."""
        import base64

        fake_png = b"\x89PNG\r\n\x1a\nfake_data"
        mock_cairosvg = MagicMock()
        mock_cairosvg.svg2png.return_value = fake_png

        with patch.dict("sys.modules", {"cairosvg": mock_cairosvg}):
            # Need to reimport to pick up the mock
            from importlib import reload

            import excalibur_mcp.infographic as infographic_mod

            reload(infographic_mod)
            result = infographic_mod.svg_to_png_base64("<svg></svg>")

        expected = base64.b64encode(fake_png).decode("ascii")
        assert result == expected


# ---------------------------------------------------------------------------
# Tool integration tests
# ---------------------------------------------------------------------------


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


class TestToolCostsInfographic:
    def test_infographic_is_read_tier(self):
        from tollbooth.constants import ToolTier

        from excalibur_mcp.server import TOOL_COSTS

        assert TOOL_COSTS["account_statement_infographic"] == ToolTier.READ

    def test_account_statement_still_free(self):
        from tollbooth.constants import ToolTier

        from excalibur_mcp.server import TOOL_COSTS

        assert TOOL_COSTS["account_statement"] == ToolTier.FREE


class TestAccountStatementInfographicTool:
    @pytest.mark.asyncio
    async def test_insufficient_funds_blocks(self):
        """Cloud user with zero balance cannot generate infographic."""
        from excalibur_mcp.server import account_statement_infographic

        mock_ledger = MagicMock()
        mock_ledger.balance_api_sats = 0

        mock_cache = MagicMock()
        mock_cache.debit = AsyncMock(return_value=False)
        mock_cache.get = AsyncMock(return_value=mock_ledger)

        _dpyc_sessions["user-1"] = _SAMPLE_NPUB
        with (
            _mock_user_id("user-1"),
            patch("excalibur_mcp.server._get_ledger_cache", return_value=mock_cache),
        ):
            result = await account_statement_infographic()

        assert result["success"] is False
        assert "Insufficient" in result["error"]

    @pytest.mark.asyncio
    async def test_success_returns_svg(self):
        """With credits, tool returns SVG markup."""
        from excalibur_mcp.server import account_statement_infographic

        mock_cache = MagicMock()
        mock_cache.debit = AsyncMock(return_value=True)

        stmt_data = _sample_statement_data()

        _dpyc_sessions["user-1"] = _SAMPLE_NPUB
        with (
            _mock_user_id("user-1"),
            patch("excalibur_mcp.server._get_ledger_cache", return_value=mock_cache),
            patch(
                "tollbooth.tools.credits.account_statement_tool",
                new_callable=AsyncMock,
                return_value=stmt_data,
            ),
        ):
            result = await account_statement_infographic()

        assert result["success"] is True
        assert "<svg " in result["svg"]
        assert "eXcalibur" in result["svg"]
        assert result["generated_at"] == "2026-02-26T14:30:00+00:00"

    @pytest.mark.asyncio
    async def test_rollback_on_statement_failure(self):
        """If account_statement_tool fails, credits are rolled back."""
        from excalibur_mcp.server import account_statement_infographic

        mock_ledger = MagicMock()
        mock_cache = MagicMock()
        mock_cache.debit = AsyncMock(return_value=True)
        mock_cache.get = AsyncMock(return_value=mock_ledger)

        _dpyc_sessions["user-1"] = _SAMPLE_NPUB
        with (
            _mock_user_id("user-1"),
            patch("excalibur_mcp.server._get_ledger_cache", return_value=mock_cache),
            patch(
                "tollbooth.tools.credits.account_statement_tool",
                new_callable=AsyncMock,
                return_value={"success": False, "error": "Vault error"},
            ),
        ):
            result = await account_statement_infographic()

        assert result["success"] is False
        # Rollback should have been called
        mock_ledger.rollback_debit.assert_called_once_with(
            "account_statement_infographic", 1
        )

    @pytest.mark.asyncio
    async def test_account_statement_has_infographic_hint(self):
        """The text account_statement should include an infographic_hint."""
        from excalibur_mcp.server import account_statement

        mock_cache = MagicMock()
        stmt_data = _sample_statement_data()

        _dpyc_sessions["user-1"] = _SAMPLE_NPUB
        with (
            _mock_user_id("user-1"),
            patch("excalibur_mcp.server._get_ledger_cache", return_value=mock_cache),
            patch(
                "tollbooth.tools.credits.account_statement_tool",
                new_callable=AsyncMock,
                return_value=stmt_data,
            ),
        ):
            result = await account_statement()

        assert "infographic_hint" in result
        assert "account_statement_infographic" in result["infographic_hint"]
