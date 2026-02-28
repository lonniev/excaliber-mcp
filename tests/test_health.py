"""Smoke test for eXcalibur-mcp server."""

import pytest


@pytest.mark.asyncio
async def test_health_returns_ok():
    """Health tool should return service info with version provenance."""
    from excalibur_mcp.server import health
    from excalibur_mcp import __version__

    result = await health()
    assert result["service"] == "excalibur-mcp"
    assert result["status"] == "ok"
    assert result["version"] == __version__
    assert "versions" in result
    assert result["versions"]["excalibur_mcp"] == __version__
    assert "tollbooth_dpyc" in result["versions"]
