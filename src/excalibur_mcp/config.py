"""eXcalibur-mcp settings loaded from environment variables."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """eXcalibur MCP server settings."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # BTCPay Server (for Lightning invoices)
    btcpay_host: str | None = None
    btcpay_store_id: str | None = None
    btcpay_api_key: str | None = None
    btcpay_tier_config: str | None = None
    btcpay_user_tiers: str | None = None

    # Credit seeding for new users (0 = disabled)
    seed_balance_sats: int = 0

    # Tollbooth royalty (operator originator payout)
    tollbooth_royalty_address: str | None = None
    tollbooth_royalty_percent: float = 0.02
    tollbooth_royalty_min_sats: int = 10

    # DPYC registry resolution (replaces dpyc_operator_npub / dpyc_authority_npub env vars)
    dpyc_registry_url: str = "https://raw.githubusercontent.com/lonniev/dpyc-community/main/members.json"
    dpyc_registry_cache_ttl_seconds: int = 300

    # Credit expiration
    credit_ttl_seconds: int | None = 604800  # 7 days

    # Commerce vault backend (pick one)
    neon_database_url: str | None = None  # Primary (serverless Postgres)

    # OpenTimestamps Bitcoin anchoring
    tollbooth_ots_enabled: str | None = None  # "true" to enable
    tollbooth_ots_calendars: str | None = None  # Comma-separated URLs

    # Credential vault location
    excalibur_vault_dir: str | None = None

    # Secure Courier (Nostr DM credential exchange)
    tollbooth_nostr_operator_nsec: str | None = None
    tollbooth_nostr_relays: str | None = None  # Comma-separated relay URLs
