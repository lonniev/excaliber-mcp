"""eXcaliber-mcp — FastMCP server for posting formatted content to X (Twitter).

Tollbooth-monetized, DPYC-native. No code shared with thebrain-mcp.
"""

from __future__ import annotations

import logging

from fastmcp import FastMCP

logger = logging.getLogger(__name__)

mcp = FastMCP("eXcaliber")


@mcp.tool()
async def health() -> dict:
    """Health check — returns service version and status. Free, no credits consumed."""
    return {
        "service": "excaliber-mcp",
        "version": "0.1.0",
        "status": "ok",
    }


def main() -> None:
    """Entry point for the eXcaliber MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
