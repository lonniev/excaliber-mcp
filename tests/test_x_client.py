"""Tests for the X API client (mocked — no real API calls)."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from excaliber_mcp.x_client import (
    TweetTooLongError,
    XAPIError,
    XClient,
    XCredentials,
    TWEET_MAX_LENGTH,
)


@pytest.fixture
def creds():
    return XCredentials(
        api_key="test-key",
        api_secret="test-secret",
        access_token="test-token",
        access_token_secret="test-token-secret",
    )


@pytest.fixture
def client(creds):
    return XClient(creds)


# ---------------------------------------------------------------------------
# Credentials
# ---------------------------------------------------------------------------


class TestXCredentials:
    def test_from_env(self, monkeypatch):
        monkeypatch.setenv("X_API_KEY", "k")
        monkeypatch.setenv("X_API_SECRET", "s")
        monkeypatch.setenv("X_ACCESS_TOKEN", "t")
        monkeypatch.setenv("X_ACCESS_TOKEN_SECRET", "ts")
        c = XCredentials.from_env()
        assert c.api_key == "k"
        assert c.access_token_secret == "ts"

    def test_from_env_missing(self, monkeypatch):
        monkeypatch.delenv("X_API_KEY", raising=False)
        with pytest.raises(KeyError):
            XCredentials.from_env()

    def test_frozen(self, creds):
        with pytest.raises(AttributeError):
            creds.api_key = "changed"


# ---------------------------------------------------------------------------
# Tweet length validation
# ---------------------------------------------------------------------------


class TestTweetLength:
    @pytest.mark.asyncio
    async def test_too_long_raises(self, client):
        long_text = "x" * (TWEET_MAX_LENGTH + 1)
        with pytest.raises(TweetTooLongError) as exc_info:
            await client.post_tweet(long_text)
        assert exc_info.value.length == TWEET_MAX_LENGTH + 1

    @pytest.mark.asyncio
    async def test_exact_limit_ok(self, client):
        """280 chars should not raise TweetTooLongError (may fail on API mock)."""
        text = "x" * TWEET_MAX_LENGTH

        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {
            "data": {"id": "123", "text": text}
        }

        with patch.object(client, "_make_oauth_client") as mock_oauth:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            mock_oauth.return_value = mock_client

            result = await client.post_tweet(text)
            assert result["tweet_id"] == "123"


# ---------------------------------------------------------------------------
# API response handling
# ---------------------------------------------------------------------------


class TestPostTweet:
    @pytest.mark.asyncio
    async def test_success(self, client):
        mock_response = MagicMock()
        mock_response.status_code = 201
        mock_response.json.return_value = {
            "data": {"id": "1234567890", "text": "Hello world"}
        }

        with patch.object(client, "_make_oauth_client") as mock_oauth:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            mock_oauth.return_value = mock_client

            result = await client.post_tweet("Hello world")

        assert result["tweet_id"] == "1234567890"
        assert "x.com" in result["tweet_url"]
        assert result["text_posted"] == "Hello world"

    @pytest.mark.asyncio
    async def test_rate_limit_429(self, client):
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_response.json.return_value = {"detail": "Too Many Requests"}

        with patch.object(client, "_make_oauth_client") as mock_oauth:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            mock_oauth.return_value = mock_client

            with pytest.raises(XAPIError) as exc_info:
                await client.post_tweet("test")
            assert exc_info.value.status_code == 429

    @pytest.mark.asyncio
    async def test_auth_error_401(self, client):
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_response.json.return_value = {"detail": "Unauthorized"}

        with patch.object(client, "_make_oauth_client") as mock_oauth:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            mock_oauth.return_value = mock_client

            with pytest.raises(XAPIError) as exc_info:
                await client.post_tweet("test")
            assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_forbidden_403(self, client):
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.json.return_value = {"title": "Forbidden", "detail": "App-only"}

        with patch.object(client, "_make_oauth_client") as mock_oauth:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            mock_oauth.return_value = mock_client

            with pytest.raises(XAPIError) as exc_info:
                await client.post_tweet("test")
            assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_unexpected_status(self, client):
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.json.return_value = {"error": "Internal Server Error"}

        with patch.object(client, "_make_oauth_client") as mock_oauth:
            mock_client = AsyncMock()
            mock_client.post.return_value = mock_response
            mock_oauth.return_value = mock_client

            with pytest.raises(XAPIError) as exc_info:
                await client.post_tweet("test")
            assert exc_info.value.status_code == 500


# ---------------------------------------------------------------------------
# TweetTooLongError details
# ---------------------------------------------------------------------------


class TestTweetTooLongError:
    def test_message_includes_length(self):
        err = TweetTooLongError(300)
        assert "300" in str(err)
        assert "20" in str(err)  # shorten by 20

    def test_stores_length(self):
        err = TweetTooLongError(285)
        assert err.length == 285
