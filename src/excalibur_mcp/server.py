"""eXcalibur-mcp — FastMCP server for posting formatted content to X (Twitter).

Tollbooth-monetized, DPYC-native. No code shared with thebrain-mcp.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from fastmcp import FastMCP

from tollbooth.constants import ToolTier

logger = logging.getLogger(__name__)

mcp = FastMCP("eXcalibur")

# Structured onboarding guidance — included in error responses so Claude
# can self-guide a first-time user through Secure Courier registration
# without the user needing to explain the process.
_ONBOARDING_NEXT_STEPS = {
    "action": "secure_courier_onboarding",
    "step_1": "Ask the user for their Nostr npub (public key). They can get one from the dpyc-oracle's how_to_join() tool.",
    "step_2": "Call request_credential_channel(recipient_npub=<npub>) to send a welcome DM to the user's Nostr client.",
    "step_3": "Tell the user to open their Nostr client (Primal, Damus, etc.) and reply to the welcome DM with their X API credentials in the JSON format shown. Credentials must NEVER appear in this chat.",
    "step_4": "Once the user confirms they replied, call receive_credentials(sender_npub=<npub>, passphrase=<passphrase>) to vault the credentials for future sessions.",
}

# Default vault directory (operator can override via EXCALIBUR_VAULT_DIR)
_DEFAULT_VAULT_DIR = os.path.join(os.path.expanduser("~"), ".excalibur", "vault")

# ---------------------------------------------------------------------------
# Tool cost table
# ---------------------------------------------------------------------------

TOOL_COSTS: dict[str, int] = {
    # Free
    "health": ToolTier.FREE,
    "service_status": ToolTier.FREE,
    "register_credentials": ToolTier.FREE,
    "activate_session": ToolTier.FREE,
    "session_status": ToolTier.FREE,
    "check_balance": ToolTier.FREE,
    "purchase_credits": ToolTier.FREE,
    "check_payment": ToolTier.FREE,
    "account_statement": ToolTier.FREE,
    "request_credential_channel": ToolTier.FREE,
    "receive_credentials": ToolTier.FREE,
    "forget_credentials": ToolTier.FREE,
    # Paid
    "post_tweet": ToolTier.READ,  # 1 api_sat (text only)
    "post_tweet_image": ToolTier.WRITE,  # 2 api_sats (with image)
    "account_statement_infographic": ToolTier.READ,  # 1 api_sat (SVG render)
}


# ---------------------------------------------------------------------------
# Settings singleton
# ---------------------------------------------------------------------------

_settings = None


def get_settings():
    """Get or create the Settings singleton."""
    global _settings
    if _settings is not None:
        return _settings
    from excalibur_mcp.config import Settings

    _settings = Settings()
    return _settings


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


def _get_effective_user_id() -> str:
    """Return the npub for the current user. Required for credit operations.

    Returns "stdio:0" in STDIO mode for local dev.
    Raises ValueError if no DPYC session is active in cloud mode.
    """
    from excalibur_mcp.vault import get_dpyc_npub

    horizon_id = _get_current_user_id()
    if not horizon_id:
        return "stdio:0"

    npub = get_dpyc_npub(horizon_id)
    if not npub:
        raise ValueError(
            "No DPYC identity active. Credit operations require an npub. "
            "Call activate_session (returning user) or follow the Secure Courier "
            "onboarding flow: ask the user for their npub, call "
            "request_credential_channel(recipient_npub=<npub>), wait for them to "
            "reply via Nostr DM, then call receive_credentials(sender_npub=<npub>, passphrase=<passphrase>). "
            "Credentials must NEVER appear in this chat."
        )
    return npub


# ---------------------------------------------------------------------------
# Credential vault singleton
# ---------------------------------------------------------------------------

_vault_instance = None


def _get_vault():
    """Get or create the FileVault singleton."""
    global _vault_instance
    if _vault_instance is not None:
        return _vault_instance
    from excalibur_mcp.vault import FileVault

    settings = get_settings()
    vault_dir = settings.excalibur_vault_dir or os.environ.get(
        "EXCALIBUR_VAULT_DIR", _DEFAULT_VAULT_DIR
    )
    _vault_instance = FileVault(vault_dir)
    return _vault_instance


# ---------------------------------------------------------------------------
# Secure Courier singleton (high-level service wrapper)
# ---------------------------------------------------------------------------

_courier_service = None


async def _on_x_credentials_received(
    sender_npub: str, credentials: dict[str, str], service: str,
) -> dict[str, Any] | None:
    """Operator callback: activate session + DPYC identity after credential receipt.

    Combines the patron's access_token/secret with the operator's api_key/secret,
    establishes the in-memory session, maps the DPYC npub identity, and seeds the
    starter balance for first-time users.
    """
    result: dict[str, Any] = {}

    user_id = _get_current_user_id()
    if not user_id:
        return result

    if not all(k in credentials for k in ("access_token", "access_token_secret")):
        return result

    api_key = os.environ.get("X_API_KEY", "")
    api_secret = os.environ.get("X_API_SECRET", "")

    if api_key and api_secret:
        from excalibur_mcp.vault import set_session

        set_session(
            user_id,
            api_key,
            api_secret,
            credentials["access_token"],
            credentials["access_token_secret"],
            npub=sender_npub,
        )
        result["session_activated"] = True
        result["dpyc_npub"] = sender_npub

        # Seed starter balance (idempotent)
        seed_applied = await _seed_balance(sender_npub)
        if seed_applied:
            result["seed_applied"] = True
            result["seed_balance_api_sats"] = get_settings().seed_balance_sats
    else:
        result["session_activated"] = False
        result["warning"] = (
            "Credentials received but operator X_API_KEY/X_API_SECRET "
            "not configured. Session not activated."
        )

    return result


def _get_courier_service():
    """Get or create the SecureCourierService singleton."""
    global _courier_service
    if _courier_service is not None:
        return _courier_service

    from tollbooth.credential_templates import CredentialTemplate, FieldSpec
    from tollbooth.nostr_credentials import NostrProfile
    from tollbooth.secure_courier import SecureCourierService

    settings = get_settings()

    nsec = settings.tollbooth_nostr_operator_nsec
    if not nsec:
        raise ValueError(
            "Secure Courier not configured. "
            "Set TOLLBOOTH_NOSTR_OPERATOR_NSEC to enable credential delivery via Nostr DM."
        )

    relays_str = settings.tollbooth_nostr_relays or "wss://relay.primal.net,wss://relay.damus.io,wss://nos.lol"
    relays = [r.strip() for r in relays_str.split(",") if r.strip()]

    templates = {
        "x": CredentialTemplate(
            service="x",
            version=2,
            fields={
                "access_token": FieldSpec(required=True, sensitive=True),
                "access_token_secret": FieldSpec(required=True, sensitive=True),
            },
            description="X/Twitter user access token (OAuth 1.0a User Context)",
        ),
    }

    # Credential vault for persistence across sessions
    from excalibur_mcp.vault import FileCredentialVault

    vault_dir = settings.excalibur_vault_dir or os.environ.get(
        "EXCALIBUR_VAULT_DIR", _DEFAULT_VAULT_DIR
    )
    credential_vault = FileCredentialVault(vault_dir)

    _courier_service = SecureCourierService(
        operator_nsec=nsec,
        relays=relays,
        templates=templates,
        credential_vault=credential_vault,
        profile=NostrProfile(
            name="excalibur-mcp",
            display_name="eXcalibur MCP",
            about=(
                "Sword-swift tweets to X — Tollbooth DPYC monetized, Nostr-native. "
                "Send credentials via encrypted DM (Secure Courier)."
            ),
            picture="https://raw.githubusercontent.com/lonniev/excalibur-mcp/main/assets/avatar.png",
            website="https://github.com/lonniev/excalibur-mcp",
        ),
        on_credentials_received=_on_x_credentials_received,
    )

    return _courier_service


# ---------------------------------------------------------------------------
# Commerce vault + LedgerCache + BTCPay singletons
# ---------------------------------------------------------------------------

_commerce_vault = None
_ledger_cache = None
_btcpay_client = None


def _get_commerce_vault():
    """Singleton commerce vault for ledger persistence.

    Primary: NeonVault (if NEON_DATABASE_URL is set).
    Raises if not configured (credit features unavailable).
    """
    global _commerce_vault
    if _commerce_vault is not None:
        return _commerce_vault

    settings = get_settings()

    if settings.neon_database_url:
        from tollbooth.vaults import NeonVault

        vault = NeonVault(database_url=settings.neon_database_url)
        import asyncio

        try:
            asyncio.ensure_future(vault.ensure_schema())
        except RuntimeError:
            pass
        logger.info("NeonVault initialized for ledger persistence.")
    else:
        raise ValueError(
            "Commerce vault not configured. Set NEON_DATABASE_URL to enable credits."
        )

    _commerce_vault = vault
    return _commerce_vault


def _get_ledger_cache():
    """Get or create the LedgerCache singleton."""
    global _ledger_cache
    if _ledger_cache is not None:
        return _ledger_cache

    from tollbooth.ledger_cache import LedgerCache

    vault = _get_commerce_vault()
    _ledger_cache = LedgerCache(vault)

    import asyncio

    try:
        asyncio.ensure_future(_ledger_cache.start_background_flush())
    except RuntimeError:
        pass

    return _ledger_cache


def _get_btcpay():
    """Get or create the BTCPayClient singleton."""
    global _btcpay_client
    if _btcpay_client is not None:
        return _btcpay_client

    from tollbooth.btcpay_client import BTCPayClient

    settings = get_settings()
    if not settings.btcpay_host or not settings.btcpay_store_id or not settings.btcpay_api_key:
        raise ValueError(
            "BTCPay not configured. Set BTCPAY_HOST, BTCPAY_STORE_ID, BTCPAY_API_KEY."
        )

    _btcpay_client = BTCPayClient(
        host=settings.btcpay_host,
        api_key=settings.btcpay_api_key,
        store_id=settings.btcpay_store_id,
    )
    return _btcpay_client


# ---------------------------------------------------------------------------
# Credential resolution: session → env vars
# ---------------------------------------------------------------------------


def _get_x_credentials():
    """Get X API credentials: per-user session first, env vars as fallback.

    The Secure Courier flow (request_credential_channel → receive_credentials)
    activates the session automatically, so by the time post_tweet runs the
    session is already populated.
    """
    from excalibur_mcp.vault import get_session
    from excalibur_mcp.x_client import XCredentials

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

    return XCredentials.from_env()


# ---------------------------------------------------------------------------
# Credit gating helpers
# ---------------------------------------------------------------------------


async def _debit_or_error(tool_name: str) -> dict[str, Any] | None:
    """Check balance and debit credits for a paid tool call.

    Returns None to proceed, or an error dict to short-circuit.
    Free tools skip gating. All paid tools require credits — including STDIO mode.
    """
    cost = TOOL_COSTS.get(tool_name, 0)
    if cost == 0:
        return None

    try:
        user_id = _get_effective_user_id()
    except ValueError as e:
        return {"success": False, "error": str(e)}

    try:
        cache = _get_ledger_cache()
    except Exception as e:
        return {
            "success": False,
            "error": (
                f"Credit system unavailable: {e}. "
                "The operator must configure NEON_DATABASE_URL to enable credits."
            ),
        }

    if not await cache.debit(user_id, tool_name, cost):
        try:
            ledger = await cache.get(user_id)
            bal = ledger.balance_api_sats
        except Exception:
            bal = 0
        return {
            "success": False,
            "error": (
                f"Insufficient balance ({bal} api_sats) "
                f"for {tool_name} ({cost} api_sats). "
                f"Use purchase_credits to add funds."
            ),
        }

    return None


async def _rollback_debit(tool_name: str) -> None:
    """Undo a debit when the downstream API call fails."""
    cost = TOOL_COSTS.get(tool_name, 0)
    if cost == 0:
        return

    try:
        user_id = _get_effective_user_id()
        cache = _get_ledger_cache()
        ledger = await cache.get(user_id)
    except Exception:
        return

    ledger.rollback_debit(tool_name, cost)
    cache.mark_dirty(user_id)


async def _with_warning(result: dict[str, Any]) -> dict[str, Any]:
    """Attach a low-balance warning to a paid tool result if balance is low."""
    try:
        from tollbooth.tools.credits import compute_low_balance_warning

        user_id = _get_effective_user_id()
        cache = _get_ledger_cache()
        ledger = await cache.get(user_id)
        settings = get_settings()
        warning = compute_low_balance_warning(ledger, settings.seed_balance_sats)
        if warning:
            result = dict(result)
            result["low_balance_warning"] = warning
    except Exception:
        pass
    return result


async def _seed_balance(npub: str) -> bool:
    """Apply seed balance for a new user (idempotent via sentinel)."""
    settings = get_settings()
    if settings.seed_balance_sats <= 0:
        return False
    try:
        cache = _get_ledger_cache()
        ledger = await cache.get(npub)
        sentinel = "seed_balance_v1"
        if sentinel not in ledger.credited_invoices:
            ledger.credit_deposit(settings.seed_balance_sats, sentinel)
            cache.mark_dirty(npub)
            await cache.flush_user(npub)
            return True
    except Exception:
        pass
    return False


# ---------------------------------------------------------------------------
# MCP Tools — Free
# ---------------------------------------------------------------------------


@mcp.tool()
async def health() -> dict:
    """Health check — returns service version and status. Free, no credits consumed."""
    import importlib.metadata as _meta

    from excalibur_mcp import __version__

    versions: dict[str, str] = {"excalibur_mcp": __version__}
    try:
        versions["tollbooth_dpyc"] = _meta.version("tollbooth-dpyc")
    except _meta.PackageNotFoundError:
        versions["tollbooth_dpyc"] = "unknown"

    return {
        "service": "excalibur-mcp",
        "version": __version__,
        "versions": versions,
        "status": "ok",
    }


@mcp.tool()
async def service_status() -> dict[str, Any]:
    """Check BTCPay configuration, connectivity, courier status, and versions.

    Operator diagnostic tool. Reports package versions, BTCPay connectivity,
    courier readiness, and cache health. Free — no credits consumed.

    Returns:
        versions: Runtime package versions (excalibur_mcp, tollbooth_dpyc, etc.).
        btcpay_host/btcpay_store_id: Configured endpoints.
        server_reachable: True/False/None (None if not configured).
        courier_status: Secure Courier readiness.
        cache_health: Ledger cache metrics (if initialized).
    """
    import importlib.metadata as _meta

    from excalibur_mcp import __version__
    from tollbooth.config import TollboothConfig
    from tollbooth.tools.credits import btcpay_status_tool

    settings = get_settings()

    btcpay_client = None
    try:
        btcpay_client = _get_btcpay()
    except ValueError:
        pass

    config = TollboothConfig(
        btcpay_host=settings.btcpay_host,
        btcpay_store_id=settings.btcpay_store_id,
        btcpay_api_key=settings.btcpay_api_key,
        btcpay_tier_config=settings.btcpay_tier_config,
        btcpay_user_tiers=settings.btcpay_user_tiers,
        seed_balance_sats=settings.seed_balance_sats,
        tollbooth_royalty_address=settings.tollbooth_royalty_address,
        tollbooth_royalty_percent=settings.tollbooth_royalty_percent,
        tollbooth_royalty_min_sats=settings.tollbooth_royalty_min_sats,
        authority_npub=settings.dpyc_authority_npub,
        credit_ttl_seconds=settings.credit_ttl_seconds,
    )

    result = await btcpay_status_tool(config, btcpay_client)

    # Augment version provenance with host-layer package
    versions = result.get("versions", {})
    versions["excalibur_mcp"] = __version__
    result["versions"] = versions

    # Courier status
    try:
        courier = _get_courier_service()
        result["courier_status"] = {
            "enabled": courier.enabled,
            "npub": courier.npub,
            "relays": courier.relays,
        }
    except Exception as exc:
        result["courier_status"] = {"enabled": False, "error": str(exc)}

    # Cache health
    try:
        cache = _get_ledger_cache()
        result["cache_health"] = cache.health()
    except Exception:
        result["cache_health"] = None

    return result


@mcp.tool()
async def session_status() -> dict[str, Any]:
    """Check the status of your current session.

    Shows whether you have an active personal session or are using
    the operator's default credentials. Also shows DPYC identity state.

    If no credentials are registered, the response includes a next_steps
    guide for the Secure Courier onboarding flow — follow it to register
    the user's X API credentials via encrypted Nostr DM (credentials
    never appear in chat).
    """
    from excalibur_mcp.vault import get_dpyc_npub, get_session

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
            "No active session. If the user has registered before, call "
            "activate_session(passphrase) to resume. Otherwise, follow "
            "the next_steps to onboard via Secure Courier — credentials "
            "travel via encrypted Nostr DM and never appear in this chat."
        ),
        "next_steps": _ONBOARDING_NEXT_STEPS,
    }


# ---------------------------------------------------------------------------
# MCP Tools — Credential Management (Free)
# ---------------------------------------------------------------------------


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
    from excalibur_mcp.vault import encrypt_credentials, set_session

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

    blob = encrypt_credentials(
        x_api_key, x_api_secret, x_access_token, x_access_token_secret,
        passphrase, npub=npub,
    )
    await vault.store(user_id, blob)

    set_session(
        user_id, x_api_key, x_api_secret, x_access_token, x_access_token_secret, npub=npub
    )

    result: dict[str, Any] = {
        "success": True,
        "message": "Credentials registered and session activated.",
        "userId": user_id,
        "dpyc_npub": npub,
    }

    # Seed starter balance (idempotent)
    seed_applied = await _seed_balance(npub)
    if seed_applied:
        result["seed_applied"] = True
        result["seed_balance_api_sats"] = get_settings().seed_balance_sats

    return result


@mcp.tool()
async def activate_session(passphrase: str) -> dict[str, Any]:
    """Activate your personal X API session by decrypting stored credentials.

    Call this at the start of each session. Provide the same passphrase you
    used during register_credentials.

    If no credentials are found (first-time user), the error response
    includes next_steps for the Secure Courier onboarding flow — follow
    those steps to register credentials via encrypted Nostr DM instead.
    Credentials must NEVER appear in this chat.

    Args:
        passphrase: The passphrase you used when registering credentials
    """
    from excalibur_mcp.vault import (
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
    except (ValueError, VaultNotConfiguredError, CredentialNotFoundError, DecryptionError) as e:
        result: dict[str, Any] = {"success": False, "error": str(e)}
        if isinstance(e, CredentialNotFoundError):
            result["next_steps"] = _ONBOARDING_NEXT_STEPS
            result["hint"] = (
                "If you already completed the Secure Courier flow, you may not "
                "have included a passphrase. Re-run receive_credentials(sender_npub=<npub>, "
                "passphrase=<passphrase>) to store credentials in the passphrase vault."
            )
        return result

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
        seed_applied = await _seed_balance(npub)
        if seed_applied:
            result["seed_applied"] = True
            result["seed_balance_api_sats"] = get_settings().seed_balance_sats
    else:
        result["dpyc_warning"] = (
            "Your vault credentials were registered before npub was required. "
            "Credit operations will not work until you re-register with an npub."
        )
    return result


# ---------------------------------------------------------------------------
# MCP Tools — Secure Courier (Free)
# ---------------------------------------------------------------------------


@mcp.tool()
async def request_credential_channel(
    service: str = "x",
    recipient_npub: str | None = None,
) -> dict[str, Any]:
    """Open a Secure Courier channel for out-of-band credential delivery.

    If you provide your npub, the service sends you a welcome DM — just
    open your Nostr client and reply to it with your credentials. No need
    to copy-paste an npub or compose a new message.

    If no npub is provided, falls back to returning the operator's npub
    and instructions for manual DM initiation.

    How it works:
    1. Call this tool with your npub — a welcome DM arrives in your Nostr inbox.
    2. Open your Nostr client (Primal, Damus, Amethyst, etc.).
    3. Reply to the welcome message with a JSON payload matching the template.
    4. Return here and call receive_credentials with your npub.

    Your credentials never appear in this chat — they travel on a
    separate, encrypted Nostr channel (the "diplomatic pouch").

    Args:
        service: Which credential template to use (default "x" for X/Twitter).
        recipient_npub: Your Nostr public key (npub1...). If provided, you'll
            receive a welcome DM to reply to instead of composing from scratch.
    """
    try:
        courier = _get_courier_service()
    except (ValueError, RuntimeError) as e:
        return {"success": False, "error": str(e)}

    try:
        return await courier.open_channel(service, recipient_npub=recipient_npub)
    except Exception as e:
        return {"success": False, "error": str(e)}


@mcp.tool()
async def receive_credentials(
    sender_npub: str,
    service: str = "x",
    passphrase: str | None = None,
) -> dict[str, Any]:
    """Pick up credentials delivered via the Secure Courier.

    If you've previously delivered credentials for this service, they'll
    be returned from the encrypted vault without any relay I/O.

    If this is your first time, the tool checks Nostr relays for your
    encrypted DM, validates it against the template, stores it in the
    vault for future sessions, and destroys the relay copy.

    Credential values are NEVER echoed back — only the field count and
    service name are returned.

    If a passphrase is provided, credentials are also stored in the
    passphrase vault so that future sessions can be activated with
    activate_session(passphrase) instead of repeating the Courier flow.

    Args:
        sender_npub: Your Nostr public key (npub1...) — the one you
            sent the DM from.
        service: Which credential template to match (default "x").
        passphrase: Optional passphrase to store credentials in the
            passphrase vault for future activate_session() calls.
    """
    try:
        courier = _get_courier_service()
    except (ValueError, RuntimeError) as e:
        return {"success": False, "error": str(e)}

    try:
        result = await courier.receive(sender_npub, service=service)
    except Exception as e:
        return {"success": False, "error": str(e)}

    # Bridge to passphrase vault for future activate_session() calls
    if passphrase and result.get("success"):
        try:
            from excalibur_mcp.vault import encrypt_credentials, get_session

            user_id = _require_user_id()
            session = get_session(user_id)
            if session:
                blob = encrypt_credentials(
                    session.x_api_key,
                    session.x_api_secret,
                    session.x_access_token,
                    session.x_access_token_secret,
                    passphrase,
                    npub=session.npub,
                )
                vault = _get_vault()
                await vault.store(user_id, blob)
                result["vault_stored"] = True
                result["message"] = (
                    result.get("message", "")
                    + " Credentials also stored in passphrase vault"
                    " — use activate_session(passphrase) in future sessions."
                )
        except Exception as e:
            result["vault_warning"] = (
                f"Courier succeeded but vault storage failed: {e}"
            )

    return result


@mcp.tool()
async def forget_credentials(sender_npub: str, service: str = "x") -> dict[str, Any]:
    """Delete vaulted credentials so you can re-deliver via Secure Courier.

    Use this when you've rotated your API keys and need to send fresh
    credentials through the diplomatic pouch.

    Args:
        sender_npub: Your Nostr public key (npub1...).
        service: Which service's credentials to forget (default "x").
    """
    try:
        courier = _get_courier_service()
    except (ValueError, RuntimeError) as e:
        return {"success": False, "error": str(e)}

    return await courier.forget(sender_npub, service=service)


# ---------------------------------------------------------------------------
# MCP Tools — Credit Management (Free)
# ---------------------------------------------------------------------------


@mcp.tool()
async def purchase_credits(amount_sats: int, certificate: str) -> dict[str, Any]:
    """Create a BTCPay Lightning invoice to purchase credits for tool calls.

    Every credit purchase requires an Authority-signed certificate. Obtain one
    by calling the Tollbooth Authority's certify_credits tool first, then pass
    the JWT here.

    Args:
        amount_sats: Number of satoshis to purchase (minimum 1, maximum 1,000,000).
        certificate: Authority-signed JWT from certify_credits. Required.
    """
    from tollbooth.tools import credits

    try:
        user_id = _get_effective_user_id()
        btcpay = _get_btcpay()
        cache = _get_ledger_cache()
    except ValueError as e:
        return {"success": False, "error": str(e)}

    settings = get_settings()
    if not settings.dpyc_authority_npub:
        return {
            "success": False,
            "error": "Operator misconfigured: DPYC_AUTHORITY_NPUB not set.",
        }

    return await credits.purchase_credits_tool(
        btcpay, cache, user_id, amount_sats,
        certificate=certificate,
        authority_npub=settings.dpyc_authority_npub,
        tier_config_json=settings.btcpay_tier_config,
        user_tiers_json=settings.btcpay_user_tiers,
        default_credit_ttl_seconds=settings.credit_ttl_seconds,
    )


@mcp.tool()
async def check_payment(invoice_id: str) -> dict[str, Any]:
    """Verify that a Lightning invoice has settled and credit the payment to your balance.

    Call this after paying the invoice from purchase_credits. Safe to call
    multiple times — credits are only granted once per invoice (idempotent).

    Args:
        invoice_id: The BTCPay invoice ID returned by purchase_credits
    """
    from tollbooth.tools import credits

    try:
        user_id = _get_effective_user_id()
        btcpay = _get_btcpay()
        cache = _get_ledger_cache()
    except ValueError as e:
        return {"success": False, "error": str(e)}

    settings = get_settings()
    return await credits.check_payment_tool(
        btcpay, cache, user_id, invoice_id,
        tier_config_json=settings.btcpay_tier_config,
        user_tiers_json=settings.btcpay_user_tiers,
        default_credit_ttl_seconds=settings.credit_ttl_seconds,
        royalty_address=settings.tollbooth_royalty_address,
        royalty_percent=settings.tollbooth_royalty_percent,
        royalty_min_sats=settings.tollbooth_royalty_min_sats,
    )


@mcp.tool()
async def check_balance() -> dict[str, Any]:
    """Check your current credit balance, tier info, usage summary, and cache health.

    Read-only — no side effects. Call anytime to check your funding level,
    review today's per-tool usage breakdown, or inspect invoice history.
    """
    from tollbooth.tools import credits

    try:
        user_id = _get_effective_user_id()
        cache = _get_ledger_cache()
    except ValueError as e:
        return {"success": False, "error": str(e)}

    settings = get_settings()
    return await credits.check_balance_tool(
        cache, user_id,
        tier_config_json=settings.btcpay_tier_config,
        user_tiers_json=settings.btcpay_user_tiers,
        default_credit_ttl_seconds=settings.credit_ttl_seconds,
    )


@mcp.tool()
async def account_statement(days: int = 30) -> dict[str, Any]:
    """Generate a customer-facing account statement with purchase history and usage.

    Free — no credits consumed.

    Args:
        days: Number of days of daily usage history to include (default 30).
    """
    from tollbooth.tools import credits

    try:
        user_id = _get_effective_user_id()
        cache = _get_ledger_cache()
    except ValueError as e:
        return {"success": False, "error": str(e)}

    result = await credits.account_statement_tool(cache, user_id, days=days)
    if result.get("success"):
        result["infographic_hint"] = (
            "Call account_statement_infographic for a visual SVG version (1 api_sat)."
        )
    return result


# ---------------------------------------------------------------------------
# MCP Tools — Paid
# ---------------------------------------------------------------------------


@mcp.tool()
async def account_statement_infographic(days: int = 30) -> dict[str, Any]:
    """Generate a visual SVG infographic of your account statement.

    Returns the same data as account_statement, rendered as a dark-themed
    SVG graphic with balance hero, metrics cards, health gauge, tranche
    table, and tool usage breakdown. Suitable for sharing or embedding.

    If cairosvg is installed, also returns a base64-encoded PNG rendition.

    Costs 1 api_sat per call.

    Args:
        days: Number of days of daily usage history to include (default 30).

    Returns:
        svg: The SVG markup string.
        png_base64: Base64-encoded PNG (only when cairosvg is installed).
        generated_at: ISO timestamp of generation.
    """
    gate = await _debit_or_error("account_statement_infographic")
    if gate:
        return gate

    try:
        user_id = _get_effective_user_id()
        cache = _get_ledger_cache()
    except ValueError as e:
        await _rollback_debit("account_statement_infographic")
        return {"success": False, "error": str(e)}

    try:
        from excalibur_mcp.infographic import render_account_infographic, svg_to_png_base64
        from tollbooth.tools import credits

        data = await credits.account_statement_tool(cache, user_id, days=days)
        if not data.get("success"):
            await _rollback_debit("account_statement_infographic")
            return data

        svg = render_account_infographic(data)
        result: dict[str, Any] = {
            "success": True,
            "svg": svg,
            "generated_at": data.get("generated_at", ""),
        }

        png_b64 = svg_to_png_base64(svg)
        if png_b64:
            result["png_base64"] = png_b64

        return await _with_warning(result)
    except Exception:
        await _rollback_debit("account_statement_infographic")
        raise


@mcp.tool()
async def post_tweet(text: str, image_url: str | None = None) -> dict:
    """Post a tweet with markdown formatting converted to Unicode rich text.

    Requires an active session with X API credentials. If you see a
    "No DPYC identity" error, the user hasn't registered yet — follow
    the Secure Courier onboarding flow: ask for their npub, call
    request_credential_channel, have them reply via Nostr DM, then
    call receive_credentials. Credentials must NEVER appear in chat.

    Accepts standard markdown inline formatting and converts it to Unicode
    Mathematical Alphanumeric Symbols that render as styled text on X:

        **bold**          → 𝗯𝗼𝗹𝗱
        *italic*          → 𝘪𝘵𝘢𝘭𝘪𝘤
        ***bold italic*** → 𝙗𝙤𝙡𝙙 𝙞𝙩𝙖𝙡𝙞𝙘
        `monospace`       → 𝚖𝚘𝚗𝚘𝚜𝚙𝚊𝚌𝚎

    Non-alphanumeric characters pass through unchanged. Unmatched
    delimiters are left as-is.

    Supports long-form posts — character limit depends on your X account
    tier (280 for free, up to 25,000 for Premium).

    Args:
        text: Tweet content with optional markdown formatting.
              Max length depends on X account tier after Unicode conversion.
        image_url: Optional URL of an image to attach to the tweet.
                   Supported formats: JPEG, PNG, GIF, WebP. Max 5 MB.

    Returns:
        tweet_id: The posted tweet's ID.
        tweet_url: Direct link to the tweet on X.
        text_posted: The Unicode-converted text that was actually sent.
        media_id: The uploaded media ID (only when image_url provided).
    """
    cost_key = "post_tweet_image" if image_url else "post_tweet"

    # Credit gating
    gate = await _debit_or_error(cost_key)
    if gate is not None:
        return gate

    from excalibur_mcp.formatter import markdown_to_unicode
    from excalibur_mcp.x_client import XAPIError, XClient

    converted = markdown_to_unicode(text)

    try:
        creds = _get_x_credentials()
    except KeyError as exc:
        await _rollback_debit(cost_key)
        return {
            "error": f"Missing X API credential: {exc}. "
            "Set X_API_KEY, X_API_SECRET, X_ACCESS_TOKEN, X_ACCESS_TOKEN_SECRET "
            "or call register_credentials to store your personal credentials."
        }

    client = XClient(creds)

    try:
        if image_url:
            result = await client.post_tweet_with_image(converted, image_url)
        else:
            result = await client.post_tweet(converted)
    except XAPIError as exc:
        await _rollback_debit(cost_key)
        return {
            "error": str(exc),
            "status_code": exc.status_code,
            "detail": exc.detail,
        }

    return await _with_warning(result)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    """Entry point for the eXcalibur MCP server."""
    mcp.run()


if __name__ == "__main__":
    main()
