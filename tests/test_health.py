"""Smoke test for eXcalibur-mcp server."""

import pytest


@pytest.mark.asyncio
async def test_health_returns_ok():
    """Health tool should return service info."""
    from excalibur_mcp.server import health

    result = await health()
    assert result["service"] == "excalibur-mcp"
    assert result["status"] == "ok"
    assert "version" in result
