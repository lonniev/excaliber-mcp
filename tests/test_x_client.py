"""Tests for the X API client (mocked — no real API calls)."""

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from excalibur_mcp.x_client import (
    TweetTooLongError,
    XAPIError,
    XClient,
    XCredentials,
    TWEET_MAX_LENGTH,
    _build_oauth1_header,
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


def _mock_response(status_code: int, body: dict) -> MagicMock:
    """Create a mock httpx response with sync .json()."""
    resp = MagicMock()
    resp.status_code = status_code
    resp.json.return_value = body
    resp.text = json.dumps(body)
    return resp


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
# OAuth 1.0a header
# ---------------------------------------------------------------------------


class TestOAuth1Header:
    def test_header_format(self):
        header = _build_oauth1_header(
            "POST", "https://api.x.com/2/tweets",
            "key", "secret", "token", "token_secret",
        )
        assert header.startswith("OAuth ")
        assert "oauth_consumer_key" in header
        assert "oauth_signature" in header
        assert "oauth_nonce" in header

    def test_different_nonces(self):
        h1 = _build_oauth1_header("POST", "https://example.com", "k", "s", "t", "ts")
        h2 = _build_oauth1_header("POST", "https://example.com", "k", "s", "t", "ts")
        assert h1 != h2  # nonce is random each time


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
        """280 chars should not raise TweetTooLongError."""
        text = "x" * TWEET_MAX_LENGTH
        mock_resp = _mock_response(201, {"data": {"id": "123", "text": text}})

        with patch("excalibur_mcp.x_client.httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.post.return_value = mock_resp
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            result = await client.post_tweet(text)
            assert result["tweet_id"] == "123"


# ---------------------------------------------------------------------------
# API response handling
# ---------------------------------------------------------------------------


class TestPostTweet:
    @pytest.mark.asyncio
    async def test_success(self, client):
        mock_resp = _mock_response(201, {
            "data": {"id": "1234567890", "text": "Hello world"}
        })

        with patch("excalibur_mcp.x_client.httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.post.return_value = mock_resp
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            result = await client.post_tweet("Hello world")

        assert result["tweet_id"] == "1234567890"
        assert "x.com" in result["tweet_url"]
        assert result["text_posted"] == "Hello world"

    @pytest.mark.asyncio
    async def test_rate_limit_429(self, client):
        mock_resp = _mock_response(429, {"detail": "Too Many Requests"})

        with patch("excalibur_mcp.x_client.httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.post.return_value = mock_resp
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            with pytest.raises(XAPIError) as exc_info:
                await client.post_tweet("test")
            assert exc_info.value.status_code == 429

    @pytest.mark.asyncio
    async def test_auth_error_401(self, client):
        mock_resp = _mock_response(401, {"detail": "Unauthorized"})

        with patch("excalibur_mcp.x_client.httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.post.return_value = mock_resp
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            with pytest.raises(XAPIError) as exc_info:
                await client.post_tweet("test")
            assert exc_info.value.status_code == 401

    @pytest.mark.asyncio
    async def test_forbidden_403(self, client):
        mock_resp = _mock_response(403, {"title": "Forbidden", "detail": "App-only"})

        with patch("excalibur_mcp.x_client.httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.post.return_value = mock_resp
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            with pytest.raises(XAPIError) as exc_info:
                await client.post_tweet("test")
            assert exc_info.value.status_code == 403

    @pytest.mark.asyncio
    async def test_unexpected_status(self, client):
        mock_resp = _mock_response(500, {"error": "Internal Server Error"})

        with patch("excalibur_mcp.x_client.httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.post.return_value = mock_resp
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            with pytest.raises(XAPIError) as exc_info:
                await client.post_tweet("test")
            assert exc_info.value.status_code == 500

    @pytest.mark.asyncio
    async def test_sends_authorization_header(self, client):
        """Verify OAuth header is sent with the request."""
        mock_resp = _mock_response(201, {"data": {"id": "999", "text": "hi"}})

        with patch("excalibur_mcp.x_client.httpx.AsyncClient") as MockClient:
            mock_instance = AsyncMock()
            mock_instance.post.return_value = mock_resp
            mock_instance.__aenter__ = AsyncMock(return_value=mock_instance)
            mock_instance.__aexit__ = AsyncMock(return_value=False)
            MockClient.return_value = mock_instance

            await client.post_tweet("hi")

            call_kwargs = mock_instance.post.call_args
            headers = call_kwargs.kwargs.get("headers", {})
            assert "Authorization" in headers
            assert headers["Authorization"].startswith("OAuth ")


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
