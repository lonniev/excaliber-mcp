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


@mcp.tool()
async def post_tweet(text: str) -> dict:
    """Post a tweet with markdown formatting converted to Unicode rich text.

    Accepts standard markdown inline formatting and converts it to Unicode
    Mathematical Alphanumeric Symbols that render as styled text on X:

        **bold**          → 𝗯𝗼𝗹𝗱
        *italic*          → 𝘪𝘵𝘢𝘭𝘪𝘤
        ***bold italic*** → 𝙗𝙤𝙡𝙙 𝙞𝙩𝙖𝙡𝙞𝙘
        `monospace`       → 𝚖𝚘𝚗𝚘𝚜𝚙𝚊𝚌𝚎

    Non-alphanumeric characters pass through unchanged. Unmatched
    delimiters are left as-is.

    Args:
        text: Tweet content with optional markdown formatting.
              Max 280 characters after Unicode conversion.

    Returns:
        tweet_id: The posted tweet's ID.
        tweet_url: Direct link to the tweet on X.
        text_posted: The Unicode-converted text that was actually sent.
    """
    # Lazy imports — keep server startup fast
    from excaliber_mcp.formatter import markdown_to_unicode
    from excaliber_mcp.x_client import TweetTooLongError, XAPIError, XClient, XCredentials

    converted = markdown_to_unicode(text)

    try:
        creds = XCredentials.from_env()
    except KeyError as exc:
        return {
            "error": f"Missing X API credential: {exc}. "
            "Set X_API_KEY, X_API_SECRET, X_ACCESS_TOKEN, X_ACCESS_TOKEN_SECRET."
        }

    client = XClient(creds)

    try:
        result = await client.post_tweet(converted)
    except TweetTooLongError as exc:
        return {"error": str(exc), "length": exc.length, "text_converted": converted}
    except XAPIError as exc:
        return {
            "error": str(exc),
            "status_code": exc.status_code,
            "detail": exc.detail,
        }

    return result


def main() -> None:
    """Entry point for the eXcaliber MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
