# eXcalibur MCP

**Sword-swift posting of pretty tweets to X (Twitter) via AI agents, monetized with Bitcoin Lightning.**

[![Version](https://img.shields.io/badge/version-0.6.0-blue)](https://github.com/lonniev/excalibur-mcp)
[![Python](https://img.shields.io/badge/python-3.10+-green)](https://python.org)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

eXcalibur is a [FastMCP](https://github.com/jlowin/fastmcp) server that lets AI agents post to X (Twitter) with rich Unicode formatting and optional images. Credentials are delivered via encrypted Nostr DMs (the "Secure Courier") so they never appear in chat. Tool calls are metered with [Tollbooth](https://github.com/lonniev/tollbooth-dpyc) pre-funded Lightning balances — no per-request payment ceremonies.

Part of the [DPYC Honor Chain](https://github.com/lonniev/dpyc-community).

## Getting Started

Connect via FastMCP Cloud — no local install needed:

```
https://www.fastmcp.cloud/mcp/lonniev/excalibur-mcp
```

### First-Time Onboarding (Secure Courier)

1. **Get your Nostr npub** — use the dpyc-oracle's `how_to_join()` tool, or any Nostr client.
2. **Call `request_credential_channel(recipient_npub=<npub>)`** — a welcome DM arrives in your Nostr inbox.
3. **Reply to the welcome DM** with your X API credentials in the JSON format shown. Credentials travel on an encrypted Nostr channel and never appear in this chat.
4. **Call `receive_credentials(sender_npub=<npub>, passphrase=<passphrase>)`** — credentials are vaulted for future sessions. Use `activate_session(passphrase)` to reactivate in any new session.

## Available Tools

### Free (Session & Billing)

| Tool | Description |
|------|-------------|
| `health` | Version and runtime status |
| `service_status` | BTCPay connectivity, Secure Courier status, component versions |
| `session_status` | Current session state (active, expired, or missing) |
| `register_credentials` | Store X API OAuth credentials encrypted with PBKDF2+Fernet |
| `activate_session` | Decrypt stored credentials via passphrase |
| `request_credential_channel` | Open Secure Courier Nostr DM channel |
| `receive_credentials` | Pick up NIP-44 encrypted credentials from Nostr relay, with optional passphrase bridge |
| `forget_credentials` | Delete vaulted credentials for re-delivery |
| `purchase_credits` | Create a Lightning invoice to fund your balance |
| `check_payment` | Poll invoice settlement and credit balance |
| `check_balance` | Balance, tier info, and usage summary |
| `account_statement` | 30-day purchase and usage ledger history |

### Paid

| Tool | Cost | Description |
|------|------|-------------|
| `post_tweet` | 1 api_sat | Post to X with markdown-to-Unicode rich text formatting |
| `post_tweet` (with image) | 2 api_sats | Post with an image URL (fetched and uploaded, up to 5 MB) |
| `account_statement_infographic` | 1 api_sat | SVG dark-themed infographic of your account activity |

## Secure Courier Protocol

Credentials never appear in the chat window. They travel on a separate, encrypted Nostr channel:

```
You (Nostr client)              eXcalibur (Operator)           Claude (Chat)
     |                                |                            |
     |    [NIP-44 encrypted DM]       |                            |
     |------------------------------->|   receive_credentials()    |
     |                                |<---------------------------|
     |                                |--- decrypt, validate ----->|
     |                                |    store in vault          |
     |                                |--- session activated ----->|
     |                                |                            |
     |    [relay copy deleted]        |                            |
```

- **NIP-44** (AES-256-CBC) encryption between your Nostr key and the operator's key
- Relay copy **deleted via NIP-09** after successful pickup
- Subsequent sessions retrieve from the local vault — no relay I/O needed

### Passphrase Bridge

When you include a `passphrase` in `receive_credentials`, your credentials are stored in *two* vaults:

1. **Courier vault** (keyed by npub, NIP-04 encrypted) — for `receive_credentials` cache hits
2. **Passphrase vault** (keyed by Horizon user_id, PBKDF2+Fernet) — for `activate_session(passphrase)`

This means you go through the Secure Courier flow once, then just call `activate_session("your passphrase")` in every future session.

## Self-Hosting

### Environment Variables

#### X API (Operator Credentials)

| Variable | Required | Description |
|----------|----------|-------------|
| `X_API_KEY` | Yes | Operator's X API consumer key |
| `X_API_SECRET` | Yes | Operator's X API consumer secret |
| `X_ACCESS_TOKEN` | No | Operator's X access token (STDIO fallback) |
| `X_ACCESS_TOKEN_SECRET` | No | Operator's X access token secret (STDIO fallback) |

#### BTCPay Server

| Variable | Required | Description |
|----------|----------|-------------|
| `BTCPAY_HOST` | Yes | BTCPay Server URL |
| `BTCPAY_STORE_ID` | Yes | Store ID for invoices |
| `BTCPAY_API_KEY` | Yes | API key with invoice permissions |
| `BTCPAY_TIER_CONFIG` | No | JSON tier multiplier config |
| `BTCPAY_USER_TIERS` | No | JSON mapping npubs to tier names |

#### DPYC Identity & Commerce

| Variable | Required | Description |
|----------|----------|-------------|
| `DPYC_OPERATOR_NPUB` | Yes | Operator's Nostr public key |
| `DPYC_AUTHORITY_NPUB` | Yes | Upstream Authority's npub for certificate verification |
| `SEED_BALANCE_SATS` | No | Starter credits for new users (default: 0) |
| `CREDIT_TTL_SECONDS` | No | Credit expiration (default: 604800 = 7 days) |
| `NEON_DATABASE_URL` | No | Neon Postgres URL for persistent ledger |

#### Secure Courier

| Variable | Required | Description |
|----------|----------|-------------|
| `TOLLBOOTH_NOSTR_OPERATOR_NSEC` | Yes | Operator's Nostr secret key for DM encryption |
| `TOLLBOOTH_NOSTR_RELAYS` | No | Comma-separated relay URLs |
| `EXCALIBUR_VAULT_DIR` | No | Credential vault directory (default: `~/.excalibur/vault`) |

#### OpenTimestamps

| Variable | Required | Description |
|----------|----------|-------------|
| `TOLLBOOTH_OTS_ENABLED` | No | `"true"` to enable Bitcoin anchoring |
| `TOLLBOOTH_OTS_CALENDARS` | No | Comma-separated OTS calendar URLs |

## Architecture

```
src/excalibur_mcp/
  server.py        FastMCP server — 14 tools, Tollbooth credit gating
  config.py        Pydantic settings from environment variables
  vault.py         PBKDF2+Fernet credential vault (OWASP 2023, 600k iterations)
  x_client.py      X API v2 client with OAuth 1.0a manual signing
  formatter.py     Markdown → Unicode rich text (bold, italic, headers)
  infographic.py   SVG account statement generator (dark theme, sword/gold branding)
```

**Key design choices:**

- **OAuth 1.0a manual signing** — not authlib — because X API v2 JSON payloads require signing the *body*, which most OAuth libraries don't support correctly.
- **PBKDF2+Fernet** for at-rest credential encryption with 600,000 iterations (OWASP 2023 recommendation).
- **Markdown → Unicode** converts `**bold**`, `*italic*`, and `# headers` to Unicode characters that render in tweets without markup syntax.

## Development

```bash
# Install in development mode
cd excalibur-mcp
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run tests (161 tests across 8 test files)
.venv/bin/pytest tests/

# Type checking
mypy src/excalibur_mcp/

# Formatting
black src/ tests/
ruff check src/ tests/
```

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.
