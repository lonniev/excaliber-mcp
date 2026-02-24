"""Markdown → Unicode Mathematical Symbol formatter.

Converts inline markdown formatting to Unicode characters that render
as styled text on X/Twitter (which only accepts plain text via API).

Supported conversions:
    **bold**         → Math Sans-Serif Bold       (U+1D5D4 block)
    *italic*         → Math Sans-Serif Italic     (U+1D608 block)
    ***bold italic***→ Math Sans-Serif Bold Italic (U+1D63C block)
    `monospace`      → Math Monospace              (U+1D670 block)
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Unicode Mathematical Alphanumeric Symbols offset tables
# Each block maps ASCII A-Z (65-90), a-z (97-122), 0-9 (48-57) to
# the corresponding Mathematical block. Not all blocks have digits.
# ---------------------------------------------------------------------------

# Math Sans-Serif Bold: U+1D5D4 (A) .. U+1D607
_BOLD_UPPER_START = 0x1D5D4  # 𝗔
_BOLD_LOWER_START = 0x1D5EE  # 𝗮
_BOLD_DIGIT_START = 0x1D7EC  # 𝟬 (Math Sans-Serif Bold Digits)

# Math Sans-Serif Italic: U+1D608 (A) .. U+1D63B
_ITALIC_UPPER_START = 0x1D608  # 𝘈
_ITALIC_LOWER_START = 0x1D622  # 𝘢
# No italic digits in Unicode standard

# Math Sans-Serif Bold Italic: U+1D63C (A) .. U+1D66F
_BOLD_ITALIC_UPPER_START = 0x1D63C  # 𝘼
_BOLD_ITALIC_LOWER_START = 0x1D656  # 𝙖
# No bold-italic digits in Unicode standard

# Math Monospace: U+1D670 (A) .. U+1D6A3
_MONO_UPPER_START = 0x1D670  # 𝙰
_MONO_LOWER_START = 0x1D68A  # 𝚊
_MONO_DIGIT_START = 0x1D7F6  # 𝟶 (Math Monospace Digits)


def _convert_char(ch: str, upper_start: int, lower_start: int,
                  digit_start: int | None = None) -> str:
    """Convert a single ASCII character to its Unicode Math counterpart."""
    code = ord(ch)
    if 65 <= code <= 90:  # A-Z
        return chr(upper_start + (code - 65))
    elif 97 <= code <= 122:  # a-z
        return chr(lower_start + (code - 97))
    elif 48 <= code <= 57 and digit_start is not None:  # 0-9
        return chr(digit_start + (code - 48))
    return ch


def to_bold(text: str) -> str:
    """Convert plain text to Math Sans-Serif Bold Unicode."""
    return "".join(
        _convert_char(ch, _BOLD_UPPER_START, _BOLD_LOWER_START, _BOLD_DIGIT_START)
        for ch in text
    )


def to_italic(text: str) -> str:
    """Convert plain text to Math Sans-Serif Italic Unicode."""
    return "".join(
        _convert_char(ch, _ITALIC_UPPER_START, _ITALIC_LOWER_START)
        for ch in text
    )


def to_bold_italic(text: str) -> str:
    """Convert plain text to Math Sans-Serif Bold Italic Unicode."""
    return "".join(
        _convert_char(ch, _BOLD_ITALIC_UPPER_START, _BOLD_ITALIC_LOWER_START)
        for ch in text
    )


def to_monospace(text: str) -> str:
    """Convert plain text to Math Monospace Unicode."""
    return "".join(
        _convert_char(ch, _MONO_UPPER_START, _MONO_LOWER_START, _MONO_DIGIT_START)
        for ch in text
    )


def markdown_to_unicode(text: str) -> str:
    """Convert markdown inline formatting to Unicode Mathematical Symbols.

    Processing order matters — longer delimiters first:
    1. ***bold italic*** (triple asterisk)
    2. **bold** (double asterisk)
    3. *italic* (single asterisk)
    4. `monospace` (backticks)

    Non-alphanumeric characters within formatted spans pass through unchanged.
    Unmatched delimiters are left as-is.

    Args:
        text: Input text with optional markdown formatting.

    Returns:
        Text with markdown formatting replaced by Unicode Math symbols.
    """
    # Phase 1: backtick monospace (non-greedy, no nesting)
    text = re.sub(r"`([^`]+)`", lambda m: to_monospace(m.group(1)), text)

    # Phase 2: bold italic (triple asterisk — must come before bold and italic)
    text = re.sub(
        r"\*\*\*(.+?)\*\*\*",
        lambda m: to_bold_italic(m.group(1)),
        text,
    )

    # Phase 3: bold (double asterisk)
    text = re.sub(
        r"\*\*(.+?)\*\*",
        lambda m: to_bold(m.group(1)),
        text,
    )

    # Phase 4: italic (single asterisk — greedy-safe after bold consumed)
    text = re.sub(
        r"\*(.+?)\*",
        lambda m: to_italic(m.group(1)),
        text,
    )

    return text
