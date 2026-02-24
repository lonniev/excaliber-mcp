"""X (Twitter) API v2 client with OAuth 1.0a authentication.

Handles tweet posting via the v2 endpoint. Credentials come from
environment variables for Task 1; multi-tenant vault in Task 2.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass

import httpx
from authlib.integrations.httpx_client import AsyncOAuth1Client

logger = logging.getLogger(__name__)

X_API_BASE = "https://api.x.com/2"
TWEET_MAX_LENGTH = 280


class XAPIError(Exception):
    """Raised when the X API returns an error response."""

    def __init__(self, status_code: int, detail: str, raw: dict | None = None):
        self.status_code = status_code
        self.detail = detail
        self.raw = raw or {}
        super().__init__(f"X API {status_code}: {detail}")


class TweetTooLongError(ValueError):
    """Raised when converted tweet text exceeds 280 characters."""

    def __init__(self, length: int):
        self.length = length
        super().__init__(
            f"Tweet is {length} characters (max {TWEET_MAX_LENGTH}). "
            f"Shorten by {length - TWEET_MAX_LENGTH} characters."
        )


@dataclass(frozen=True)
class XCredentials:
    """OAuth 1.0a credentials for X API access."""

    api_key: str
    api_secret: str
    access_token: str
    access_token_secret: str

    @classmethod
    def from_env(cls) -> XCredentials:
        """Load credentials from environment variables.

        Expected env vars:
            X_API_KEY, X_API_SECRET, X_ACCESS_TOKEN, X_ACCESS_TOKEN_SECRET
        """
        return cls(
            api_key=os.environ["X_API_KEY"],
            api_secret=os.environ["X_API_SECRET"],
            access_token=os.environ["X_ACCESS_TOKEN"],
            access_token_secret=os.environ["X_ACCESS_TOKEN_SECRET"],
        )


class XClient:
    """Async X API v2 client with OAuth 1.0a signing."""

    def __init__(self, credentials: XCredentials) -> None:
        self._creds = credentials

    def _make_oauth_client(self) -> AsyncOAuth1Client:
        """Create a fresh OAuth1 client for a request."""
        return AsyncOAuth1Client(
            client_id=self._creds.api_key,
            client_secret=self._creds.api_secret,
            token=self._creds.access_token,
            token_secret=self._creds.access_token_secret,
        )

    async def post_tweet(self, text: str) -> dict:
        """Post a tweet to X.

        Args:
            text: The tweet text (already Unicode-converted). Max 280 chars.

        Returns:
            dict with tweet_id, tweet_url, text_posted.

        Raises:
            TweetTooLongError: If text exceeds 280 characters.
            XAPIError: If the X API returns an error.
        """
        if len(text) > TWEET_MAX_LENGTH:
            raise TweetTooLongError(len(text))

        client = self._make_oauth_client()
        try:
            response = await client.post(
                f"{X_API_BASE}/tweets",
                json={"text": text},
                headers={"Content-Type": "application/json"},
            )
        finally:
            await client.aclose()

        if response.status_code == 429:
            raise XAPIError(429, "Rate limited — try again later", response.json())

        if response.status_code in (401, 403):
            body = response.json()
            detail = body.get("detail", body.get("title", "Authentication failed"))
            raise XAPIError(response.status_code, detail, body)

        if response.status_code != 201:
            try:
                body = response.json()
            except Exception:
                body = {"raw": response.text}
            raise XAPIError(
                response.status_code,
                f"Unexpected response: {response.status_code}",
                body,
            )

        data = response.json()["data"]
        tweet_id = data["id"]

        return {
            "tweet_id": tweet_id,
            "tweet_url": f"https://x.com/i/status/{tweet_id}",
            "text_posted": text,
        }
