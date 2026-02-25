"""eXcaliber-mcp — FastMCP server for posting formatted content to X (Twitter).

Tollbooth-monetized, DPYC-native. No code shared with thebrain-mcp.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from fastmcp import FastMCP

logger = logging.getLogger(__name__)

mcp = FastMCP("eXcaliber")

# Default vault directory (operator can override via EXCALIBER_VAULT_DIR)
_DEFAULT_VAULT_DIR = os.path.join(os.path.expanduser("~"), ".excaliber", "vault")


# ---------------------------------------------------------------------------
# Horizon auth helpers
# ---------------------------------------------------------------------------


def _get_current_user_id() -> str | None:
    """Extract FastMCP Cloud user ID from request headers.

    Returns None in STDIO mode (local dev) or when no auth headers present.
    """
    try:
        from fastmcp.server.dependencies import get_http_headers

        headers = get_http_headers(include_all=True)
        return headers.get("fastmcp-cloud-user")
    except Exception:
        return None


def _require_user_id() -> str:
    """Extract user ID or raise ValueError."""
    user_id = _get_current_user_id()
    if not user_id:
        raise ValueError(
            "Multi-tenant credentials require FastMCP Cloud (Horizon). "
            "In STDIO mode, set X_API_KEY etc. as environment variables."
        )
    return user_id


# ---------------------------------------------------------------------------
# Vault singleton
# ---------------------------------------------------------------------------

_vault_instance = None


def _get_vault():
    """Get or create the FileVault singleton."""
    global _vault_instance
    if _vault_instance is not None:
        return _vault_instance
    from excaliber_mcp.vault import FileVault

    vault_dir = os.environ.get("EXCALIBER_VAULT_DIR", _DEFAULT_VAULT_DIR)
    _vault_instance = FileVault(vault_dir)
    return _vault_instance


# ---------------------------------------------------------------------------
# Credential resolution: session → env vars
# ---------------------------------------------------------------------------


def _get_x_credentials():
    """Get X API credentials: per-user session first, env vars as fallback.

    Returns XCredentials.
    """
    from excaliber_mcp.vault import get_session
    from excaliber_mcp.x_client import XCredentials

    user_id = _get_current_user_id()
    if user_id:
        session = get_session(user_id)
        if session:
            return XCredentials(
                api_key=session.x_api_key,
                api_secret=session.x_api_secret,
                access_token=session.x_access_token,
                access_token_secret=session.x_access_token_secret,
            )

    # Fallback to env vars (operator's credentials or STDIO mode)
    return XCredentials.from_env()


# ---------------------------------------------------------------------------
# MCP Tools
# ---------------------------------------------------------------------------


@mcp.tool()
async def health() -> dict:
    """Health check — returns service version and status. Free, no credits consumed."""
    return {
        "service": "excaliber-mcp",
        "version": "0.2.0",
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
    from excaliber_mcp.formatter import markdown_to_unicode
    from excaliber_mcp.x_client import TweetTooLongError, XAPIError, XClient

    converted = markdown_to_unicode(text)

    try:
        creds = _get_x_credentials()
    except KeyError as exc:
        return {
            "error": f"Missing X API credential: {exc}. "
            "Set X_API_KEY, X_API_SECRET, X_ACCESS_TOKEN, X_ACCESS_TOKEN_SECRET "
            "or call register_credentials to store your personal credentials."
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


@mcp.tool()
async def register_credentials(
    x_api_key: str,
    x_api_secret: str,
    x_access_token: str,
    x_access_token_secret: str,
    passphrase: str,
    npub: str,
) -> dict[str, Any]:
    """Register your X API credentials for multi-tenant access.

    First-time setup: encrypts your X API OAuth credentials with your
    passphrase and stores the encrypted blob in the operator's credential
    vault. The passphrase is never stored — you will need it each session
    to activate access.

    Your DPYC npub (Nostr public key) is required — it serves as your
    persistent identity for credit operations. Obtain one from the
    dpyc-oracle's how_to_join() tool if you don't have one yet.

    Args:
        x_api_key: Your X API consumer key
        x_api_secret: Your X API consumer secret
        x_access_token: Your X API access token
        x_access_token_secret: Your X API access token secret
        passphrase: A passphrase to encrypt your credentials (remember this!)
        npub: Your Nostr public key in bech32 format (npub1...). Required for
            credit operations. Get one via the dpyc-oracle's how_to_join() tool.
    """
    from excaliber_mcp.vault import encrypt_credentials, set_session

    # Validate npub format
    if not npub.startswith("npub1") or len(npub) < 60:
        return {
            "success": False,
            "error": (
                "Invalid npub format. Must start with 'npub1' and be at least 60 characters. "
                "Get your npub from the dpyc-oracle's how_to_join() tool."
            ),
        }

    try:
        user_id = _require_user_id()
    except ValueError as e:
        return {"success": False, "error": str(e)}

    try:
        vault = _get_vault()
    except Exception as e:
        return {"success": False, "error": f"Vault not available: {e}"}

    # Encrypt and store
    blob = encrypt_credentials(
        x_api_key, x_api_secret, x_access_token, x_access_token_secret,
        passphrase, npub=npub,
    )
    await vault.store(user_id, blob)

    # Activate session immediately
    set_session(user_id, x_api_key, x_api_secret, x_access_token, x_access_token_secret, npub=npub)

    return {
        "success": True,
        "message": "Credentials registered and session activated.",
        "userId": user_id,
        "dpyc_npub": npub,
    }


@mcp.tool()
async def activate_session(passphrase: str) -> dict[str, Any]:
    """Activate your personal X API session by decrypting stored credentials.

    Call this at the start of each session. Provide the same passphrase you
    used during register_credentials.

    Args:
        passphrase: The passphrase you used when registering credentials
    """
    from excaliber_mcp.vault import (
        CredentialNotFoundError,
        DecryptionError,
        VaultNotConfiguredError,
        decrypt_credentials,
        set_session,
    )

    try:
        user_id = _require_user_id()
        vault = _get_vault()
        blob = await vault.fetch(user_id)
        creds = decrypt_credentials(blob, passphrase)
    except ValueError as e:
        return {"success": False, "error": str(e)}
    except VaultNotConfiguredError as e:
        return {"success": False, "error": str(e)}
    except CredentialNotFoundError as e:
        return {"success": False, "error": str(e)}
    except DecryptionError as e:
        return {"success": False, "error": str(e)}

    # Activate session in-memory
    npub = creds.get("npub")
    set_session(
        user_id,
        creds["x_api_key"],
        creds["x_api_secret"],
        creds["x_access_token"],
        creds["x_access_token_secret"],
        npub=npub,
    )

    result: dict[str, Any] = {
        "success": True,
        "message": "Session activated. post_tweet now uses your personal credentials.",
    }
    if npub:
        result["dpyc_npub"] = npub
    else:
        result["dpyc_warning"] = (
            "Your vault credentials were registered before npub was required. "
            "Credit operations will not work until you re-register with an npub."
        )
    return result


@mcp.tool()
async def session_status() -> dict[str, Any]:
    """Check the status of your current session.

    Shows whether you have an active personal session or are using
    the operator's default credentials. Also shows DPYC identity state.
    """
    from excaliber_mcp.vault import get_dpyc_npub, get_session

    user_id = _get_current_user_id()
    if not user_id:
        return {
            "mode": "stdio",
            "message": "Running in STDIO mode (local dev). Using operator environment credentials.",
            "personal_session": False,
        }

    session = get_session(user_id)
    if session:
        result: dict[str, Any] = {
            "mode": "cloud",
            "personal_session": True,
            "session_age_seconds": session.age_seconds,
            "message": "Personal X API credentials active.",
        }
        npub = get_dpyc_npub(user_id)
        if npub:
            result["dpyc_npub"] = npub
        else:
            result["dpyc_warning"] = "No DPYC identity active."
        return result

    return {
        "mode": "cloud",
        "personal_session": False,
        "message": (
            "No active session. Call register_credentials (first time) "
            "or activate_session (returning user) to use your personal X API credentials. "
            "Falling back to operator's default credentials."
        ),
    }


def main() -> None:
    """Entry point for the eXcaliber MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
