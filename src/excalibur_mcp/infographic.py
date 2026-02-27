"""SVG infographic generator for account statements.

Produces a dark-themed, sword-accented SVG infographic from
the structured data returned by ``account_statement_tool``.  Pure Python
-- no external dependencies (matplotlib, Pillow, etc.).

Branding: eXcalibur MCP -- sword-swift tweets to X.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
from typing import Any
from xml.sax.saxutils import escape


# ---------------------------------------------------------------------------
# Colour palette -- dark steel with gold/amber sword-theme accents
# ---------------------------------------------------------------------------

BG_DARK = "#0d1117"
BG_CARD = "#161b22"
BG_CARD_ALT = "#1c2333"
ACCENT_GOLD = "#d4a017"       # Excalibur gold
ACCENT_STEEL = "#7c8a9a"      # Blade steel
ACCENT_GREEN = "#2ecc71"      # Balance positive
ACCENT_RED = "#e74c3c"        # Warnings / expired
ACCENT_BLUE = "#58a6ff"       # Links / sources
TEXT_WHITE = "#e6edf3"
TEXT_GRAY = "#8b949e"
TEXT_DIM = "#484f58"
BORDER = "#30363d"

# ---------------------------------------------------------------------------
# Layout constants
# ---------------------------------------------------------------------------

WIDTH = 640
CARD_X = 24
CARD_W = WIDTH - 2 * CARD_X
CARD_R = 10  # border-radius


def _card(y: int, h: int, fill: str = BG_CARD) -> str:
    return (
        f'<rect x="{CARD_X}" y="{y}" width="{CARD_W}" height="{h}" '
        f'rx="{CARD_R}" fill="{fill}" stroke="{BORDER}" stroke-width="1"/>'
    )


def _text(
    x: int,
    y: int,
    text: str,
    *,
    size: int = 14,
    fill: str = TEXT_WHITE,
    weight: str = "normal",
    anchor: str = "start",
    family: str = "monospace",
) -> str:
    return (
        f'<text x="{x}" y="{y}" font-size="{size}" fill="{fill}" '
        f'font-weight="{weight}" text-anchor="{anchor}" '
        f'font-family="{family}">{escape(str(text))}</text>'
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def render_account_infographic(data: dict[str, Any]) -> str:
    """Return SVG markup for a visual account statement.

    *data* is the dict returned by ``account_statement_tool``.
    Branded for eXcalibur MCP with sword motif and steel/gold palette.
    """
    summary = data.get("account_summary", {})
    balance = summary.get("balance_api_sats", 0)
    deposited = summary.get("total_deposited_api_sats", 0)
    consumed = summary.get("total_consumed_api_sats", 0)
    expired = summary.get("total_expired_api_sats", 0)
    tranches: list[dict[str, Any]] = data.get("active_tranches", [])
    tool_usage: list[dict[str, Any]] = data.get("tool_usage_all_time", [])
    generated_at = data.get("generated_at", datetime.now(timezone.utc).isoformat())

    parts: list[str] = []
    cy = 16  # current y cursor

    # -- Header ---------------------------------------------------------------
    header_h = 80
    parts.append(_card(cy, header_h))
    # Sword emoji as brand icon
    parts.append(_text(CARD_X + 20, cy + 46, "\u2694", size=28,
                       fill=ACCENT_GOLD, family="sans-serif"))
    parts.append(_text(CARD_X + 48, cy + 38, "eXcalibur",
                       size=22, weight="bold", family="sans-serif"))
    parts.append(_text(CARD_X + 48, cy + 60, "Account Statement",
                       size=14, fill=ACCENT_GOLD, family="sans-serif"))
    # timestamp
    ts_short = generated_at[:19].replace("T", " ") + " UTC"
    parts.append(_text(WIDTH - CARD_X - 16, cy + 64, ts_short,
                       size=9, fill=TEXT_DIM, anchor="end"))
    cy += header_h + 12

    # -- Hero balance ---------------------------------------------------------
    hero_h = 100
    parts.append(_card(cy, hero_h))
    parts.append(_text(WIDTH // 2, cy + 30,
                       "A V A I L A B L E   B A L A N C E",
                       size=10, fill=TEXT_GRAY, weight="bold",
                       anchor="middle", family="sans-serif"))
    parts.append(_text(WIDTH // 2, cy + 72, f"{balance:,}",
                       size=48, fill=ACCENT_GREEN, weight="bold",
                       anchor="middle"))
    parts.append(_text(WIDTH // 2 + 100, cy + 72, "api_sats",
                       size=13, fill=TEXT_GRAY, anchor="start",
                       family="sans-serif"))
    cy += hero_h + 12

    # -- Metrics row ----------------------------------------------------------
    metrics = [
        ("\u2B07", "DEPOSITED", deposited, ACCENT_BLUE),
        ("\u2B06", "CONSUMED", consumed, ACCENT_GOLD),
        ("\u23F1", "EXPIRED", expired, ACCENT_RED if expired > 0 else TEXT_DIM),
    ]
    metric_w = (CARD_W - 24) // 3
    metric_h = 80
    for i, (icon, label, value, colour) in enumerate(metrics):
        mx = CARD_X + 8 + i * (metric_w + 8)
        parts.append(
            f'<rect x="{mx}" y="{cy}" width="{metric_w}" height="{metric_h}" '
            f'rx="8" fill="{BG_CARD_ALT}" stroke="{BORDER}" stroke-width="0.8"/>'
        )
        parts.append(_text(mx + metric_w // 2, cy + 24, icon,
                           size=16, fill=colour, anchor="middle",
                           family="sans-serif"))
        parts.append(_text(mx + metric_w // 2, cy + 50, f"{value:,}",
                           size=20, fill=colour, weight="bold",
                           anchor="middle"))
        parts.append(_text(mx + metric_w // 2, cy + 68, label,
                           size=8, fill=TEXT_GRAY, weight="bold",
                           anchor="middle", family="sans-serif"))
    cy += metric_h + 12

    # -- Balance health gauge -------------------------------------------------
    gauge_h = 130
    parts.append(_card(cy, gauge_h))
    parts.append(_text(CARD_X + 16, cy + 24, "BALANCE HEALTH",
                       size=10, fill=TEXT_GRAY, weight="bold",
                       family="sans-serif"))

    bar_x = CARD_X + 16
    bar_y = cy + 38
    bar_w = CARD_W - 32
    bar_h = 26
    pct_remaining = (balance / deposited * 100) if deposited > 0 else 100
    fill_w = max(int(bar_w * pct_remaining / 100), 0)

    parts.append(
        f'<rect x="{bar_x}" y="{bar_y}" width="{bar_w}" height="{bar_h}" '
        f'rx="6" fill="#1a1a2e" stroke="{BORDER}" stroke-width="0.5"/>'
    )
    if fill_w > 0:
        parts.append(
            f'<rect x="{bar_x}" y="{bar_y}" width="{fill_w}" height="{bar_h}" '
            f'rx="6" fill="{ACCENT_GREEN}" opacity="0.8"/>'
        )
    parts.append(_text(bar_x + bar_w // 2, bar_y + 18,
                       f"{pct_remaining:.1f}% remaining",
                       size=12, fill=TEXT_WHITE, weight="bold",
                       anchor="middle", family="sans-serif"))

    # Legend
    ly = bar_y + bar_h + 20
    parts.append(_text(bar_x, ly, f"\u25CF {balance:,} remaining",
                       size=10, fill=ACCENT_GREEN))
    parts.append(_text(bar_x + 180, ly, f"\u25CF {consumed:,} consumed",
                       size=10, fill=ACCENT_GOLD))
    parts.append(_text(bar_x + 360, ly, f"\u25CF {expired:,} expired",
                       size=10, fill=TEXT_DIM))

    total_calls = sum(t.get("calls", 0) for t in tool_usage)
    avg_cost = consumed / total_calls if total_calls else 0
    parts.append(_text(bar_x, ly + 20,
                       f"Efficiency: {pct_remaining:.1f}%  |  "
                       f"Cost per call: {avg_cost:.1f} api_sats  |  "
                       f"Total calls: {total_calls}",
                       size=9, fill=TEXT_DIM))
    cy += gauge_h + 12

    # -- Active credit tranches -----------------------------------------------
    tranche_rows = max(len(tranches), 1)
    tranche_h = 50 + tranche_rows * 24
    parts.append(_card(cy, tranche_h))
    parts.append(_text(CARD_X + 16, cy + 24, "ACTIVE CREDIT TRANCHES",
                       size=10, fill=TEXT_GRAY, weight="bold",
                       family="sans-serif"))

    cols_t = [CARD_X + 16, CARD_X + 160, CARD_X + 310, CARD_X + 440]
    headers_t = ["SOURCE", "GRANTED", "ORIGINAL", "REMAINING"]
    for x, h in zip(cols_t, headers_t):
        parts.append(_text(x, cy + 44, h, size=8, fill=TEXT_DIM, weight="bold"))
    parts.append(
        f'<line x1="{CARD_X + 12}" y1="{cy + 50}" '
        f'x2="{WIDTH - CARD_X - 12}" y2="{cy + 50}" '
        f'stroke="{BORDER}" stroke-width="0.5"/>'
    )

    if tranches:
        for i, t in enumerate(tranches):
            ry = cy + 68 + i * 24
            source = t.get("invoice_id", "unknown")
            if source.startswith("seed"):
                source = "Seed (v1)"
            elif len(source) > 14:
                source = source[:12] + ".."
            granted = str(t.get("granted_at", ""))[:10]
            original = f'{t.get("original_sats", 0):,}'
            remaining = f'{t.get("remaining_sats", 0):,}'
            parts.append(_text(cols_t[0], ry, source, size=10, fill=ACCENT_BLUE))
            parts.append(_text(cols_t[1], ry, granted, size=10))
            parts.append(_text(cols_t[2], ry, original, size=10))
            parts.append(_text(cols_t[3], ry, remaining, size=10,
                               fill=ACCENT_GREEN, weight="bold"))
    else:
        parts.append(_text(cols_t[0], cy + 68, "No active tranches",
                           size=10, fill=TEXT_DIM))
    cy += tranche_h + 12

    # -- Tool usage -----------------------------------------------------------
    usage_rows = max(len(tool_usage), 1)
    usage_h = 50 + usage_rows * 24
    parts.append(_card(cy, usage_h))
    parts.append(_text(CARD_X + 16, cy + 24, "TOOL USAGE (ALL-TIME)",
                       size=10, fill=TEXT_GRAY, weight="bold",
                       family="sans-serif"))

    cols_u = [CARD_X + 16, CARD_X + 260, CARD_X + 370, CARD_X + 480]
    headers_u = ["TOOL", "CALLS", "COST", "AVG"]
    for x, h in zip(cols_u, headers_u):
        parts.append(_text(x, cy + 44, h, size=8, fill=TEXT_DIM, weight="bold"))
    parts.append(
        f'<line x1="{CARD_X + 12}" y1="{cy + 50}" '
        f'x2="{WIDTH - CARD_X - 12}" y2="{cy + 50}" '
        f'stroke="{BORDER}" stroke-width="0.5"/>'
    )

    if tool_usage:
        for i, u in enumerate(tool_usage):
            ry = cy + 68 + i * 24
            tool_name = u.get("tool", "?")
            calls = u.get("calls", 0)
            cost = u.get("api_sats", 0)
            avg = cost / calls if calls else 0
            parts.append(_text(cols_u[0], ry, tool_name, size=10, fill=ACCENT_BLUE))
            parts.append(_text(cols_u[1], ry, str(calls), size=10))
            suffix = "s" if cost != 1 else ""
            parts.append(_text(cols_u[2], ry, f"{cost} sat{suffix}",
                               size=10, fill=ACCENT_GOLD))
            parts.append(_text(cols_u[3], ry, f"{avg:.1f}", size=10, fill=TEXT_GRAY))
    else:
        parts.append(_text(cols_u[0], cy + 68, "No usage yet",
                           size=10, fill=TEXT_DIM))
    cy += usage_h + 12

    # -- Footer ---------------------------------------------------------------
    footer_h = 60
    parts.append(_text(WIDTH // 2, cy + 16,
                       "DPYC \u2022 Don\u2019t Pester Your Customer",
                       size=10, fill=TEXT_DIM, anchor="middle",
                       family="sans-serif"))
    parts.append(_text(WIDTH // 2, cy + 34,
                       "Powered by Bitcoin Lightning \u26A1 \u2022 eXcalibur MCP \u2694",
                       size=9, fill=TEXT_DIM, anchor="middle",
                       family="sans-serif"))
    cy += footer_h

    # -- Assemble SVG ---------------------------------------------------------
    total_h = cy + 8
    body = "\n  ".join(parts)
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'width="{WIDTH}" height="{total_h}" '
        f'viewBox="0 0 {WIDTH} {total_h}">\n'
        f'  <rect width="{WIDTH}" height="{total_h}" fill="{BG_DARK}"/>\n'
        f"  {body}\n"
        f"</svg>"
    )


def svg_to_png_base64(svg: str) -> str | None:
    """Convert SVG string to base64-encoded PNG using cairosvg.

    Returns None if cairosvg is not installed (optional dependency).
    """
    try:
        import cairosvg  # type: ignore[import-untyped]
    except ImportError:
        return None

    png_bytes = cairosvg.svg2png(bytestring=svg.encode("utf-8"))
    return base64.b64encode(png_bytes).decode("ascii")
