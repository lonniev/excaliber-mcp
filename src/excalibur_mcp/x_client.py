"""X (Twitter) API v2 client with OAuth 1.0a authentication.

Handles tweet posting via the v2 endpoint. Uses manual OAuth 1.0a
header signing (not authlib's AsyncOAuth1Client) because the X API v2
requires JSON bodies, and authlib mangles them during signature computation.

Credentials come from environment variables for Task 1; multi-tenant
vault planned for a future task.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import secrets
import time
import urllib.parse
from dataclasses import dataclass

import httpx

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


def _build_oauth1_header(
    method: str,
    url: str,
    consumer_key: str,
    consumer_secret: str,
    token: str,
    token_secret: str,
) -> str:
    """Build an OAuth 1.0a Authorization header (HMAC-SHA1, header-only).

    This produces a header-based OAuth signature that does NOT include
    the request body in the signature base string. Required for X API v2
    which uses JSON bodies (OAuth 1.0a body signing only works with
    application/x-www-form-urlencoded).
    """
    oauth_params = {
        "oauth_consumer_key": consumer_key,
        "oauth_nonce": secrets.token_hex(16),
        "oauth_signature_method": "HMAC-SHA1",
        "oauth_timestamp": str(int(time.time())),
        "oauth_token": token,
        "oauth_version": "1.0",
    }

    # Build signature base string (RFC 5849 §3.4.1)
    param_str = "&".join(
        f"{k}={urllib.parse.quote(v, safe='')}"
        for k, v in sorted(oauth_params.items())
    )
    base_str = (
        f"{method}&"
        f"{urllib.parse.quote(url, safe='')}&"
        f"{urllib.parse.quote(param_str, safe='')}"
    )

    # Sign with HMAC-SHA1
    signing_key = (
        f"{urllib.parse.quote(consumer_secret, safe='')}&"
        f"{urllib.parse.quote(token_secret, safe='')}"
    )
    signature = base64.b64encode(
        hmac.new(signing_key.encode(), base_str.encode(), hashlib.sha1).digest()
    ).decode()

    oauth_params["oauth_signature"] = signature

    # Format as Authorization header
    return "OAuth " + ", ".join(
        f'{k}="{urllib.parse.quote(v, safe="")}"'
        for k, v in sorted(oauth_params.items())
    )


class XClient:
    """Async X API v2 client with OAuth 1.0a header signing."""

    def __init__(self, credentials: XCredentials) -> None:
        self._creds = credentials

    def _auth_header(self, method: str, url: str) -> str:
        """Generate OAuth 1.0a Authorization header for a request."""
        return _build_oauth1_header(
            method=method,
            url=url,
            consumer_key=self._creds.api_key,
            consumer_secret=self._creds.api_secret,
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

        url = f"{X_API_BASE}/tweets"
        auth_header = self._auth_header("POST", url)

        async with httpx.AsyncClient() as client:
            response = await client.post(
                url,
                json={"text": text},
                headers={"Authorization": auth_header},
            )

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
