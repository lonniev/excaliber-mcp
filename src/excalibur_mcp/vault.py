"""Multi-tenant credential vault for eXcalibur-mcp.

Mirrors thebrain-mcp's vault pattern: PBKDF2 key derivation + Fernet
symmetric encryption. Each user's X API OAuth credentials are encrypted
with their passphrase, stored as a JSON envelope, and decrypted per-session.

The passphrase is never stored — users must remember it.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import time
from dataclasses import dataclass, field

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class VaultError(Exception):
    """Base exception for vault operations."""


class VaultNotConfiguredError(VaultError):
    """Raised when the vault storage backend is not configured."""


class CredentialNotFoundError(VaultError):
    """Raised when no credentials are stored for a user."""


class DecryptionError(VaultError):
    """Raised when credential decryption fails (wrong passphrase or corrupted blob)."""


# ---------------------------------------------------------------------------
# Encryption helpers (PBKDF2 + Fernet)
# ---------------------------------------------------------------------------

_PBKDF2_ITERATIONS = 600_000  # OWASP 2023 recommendation


def derive_key(passphrase: str, salt: bytes) -> bytes:
    """Derive a Fernet key from passphrase + salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=_PBKDF2_ITERATIONS,
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


def encrypt_credentials(
    x_api_key: str,
    x_api_secret: str,
    x_access_token: str,
    x_access_token_secret: str,
    passphrase: str,
    *,
    npub: str | None = None,
) -> str:
    """Encrypt X API credentials into a JSON envelope with embedded salt.

    Returns a JSON string: {"v": 1, "salt": "<base64>", "data": "<fernet token>"}.
    """
    salt = os.urandom(16)
    key = derive_key(passphrase, salt)
    f = Fernet(key)

    payload_dict: dict[str, str] = {
        "x_api_key": x_api_key,
        "x_api_secret": x_api_secret,
        "x_access_token": x_access_token,
        "x_access_token_secret": x_access_token_secret,
    }
    if npub:
        payload_dict["npub"] = npub

    payload = json.dumps(payload_dict).encode("utf-8")
    ciphertext = f.encrypt(payload)

    return json.dumps({
        "v": 1,
        "salt": base64.b64encode(salt).decode("ascii"),
        "data": ciphertext.decode("ascii"),
    })


def decrypt_credentials(blob: str, passphrase: str) -> dict[str, str]:
    """Decrypt a credential blob. Returns dict with x_api_key, x_api_secret, etc.

    Raises DecryptionError on wrong passphrase or corrupted data.
    """
    try:
        envelope = json.loads(blob)
    except (json.JSONDecodeError, TypeError) as e:
        raise DecryptionError("Credential blob is corrupted (invalid JSON).") from e

    if "salt" not in envelope or "data" not in envelope:
        raise DecryptionError("Credential blob is corrupted (missing fields).")

    try:
        salt = base64.b64decode(envelope["salt"])
        key = derive_key(passphrase, salt)
        f = Fernet(key)
        plaintext = f.decrypt(envelope["data"].encode("ascii"))
        return json.loads(plaintext)
    except InvalidToken:
        raise DecryptionError("Wrong passphrase.")
    except Exception as e:
        raise DecryptionError("Credential blob is corrupted.") from e


# ---------------------------------------------------------------------------
# In-memory session management
# ---------------------------------------------------------------------------

SESSION_TTL_SECONDS = 3600  # 1 hour


@dataclass
class UserSession:
    """Per-user session holding decrypted X API credentials."""

    x_api_key: str
    x_api_secret: str
    x_access_token: str
    x_access_token_secret: str
    npub: str | None = None
    created_at: float = field(default_factory=time.time)

    def __repr__(self) -> str:
        age = int(time.time() - self.created_at)
        return (
            f"UserSession(npub={self.npub!r}, age={age}s, "
            f"x_api_key=<redacted>, x_api_secret=<redacted>)"
        )

    @property
    def is_expired(self) -> bool:
        return (time.time() - self.created_at) > SESSION_TTL_SECONDS

    @property
    def age_seconds(self) -> int:
        return int(time.time() - self.created_at)


_sessions: dict[str, UserSession] = {}  # Horizon user_id → session
_dpyc_sessions: dict[str, str] = {}  # Horizon user_id → npub


def get_session(user_id: str) -> UserSession | None:
    """Get active session, returning None if expired or absent."""
    session = _sessions.get(user_id)
    if session and session.is_expired:
        del _sessions[user_id]
        return None
    return session


def set_session(
    user_id: str,
    x_api_key: str,
    x_api_secret: str,
    x_access_token: str,
    x_access_token_secret: str,
    npub: str | None = None,
) -> UserSession:
    """Create or replace a session for a user."""
    session = UserSession(
        x_api_key=x_api_key,
        x_api_secret=x_api_secret,
        x_access_token=x_access_token,
        x_access_token_secret=x_access_token_secret,
        npub=npub,
    )
    _sessions[user_id] = session
    if npub:
        _dpyc_sessions[user_id] = npub
    return session


def clear_session(user_id: str) -> None:
    """Remove a session."""
    _sessions.pop(user_id, None)
    _dpyc_sessions.pop(user_id, None)


def get_dpyc_npub(user_id: str) -> str | None:
    """Get the DPYC npub for a Horizon user, if activated."""
    return _dpyc_sessions.get(user_id)


# ---------------------------------------------------------------------------
# Credential storage (file-based vault)
# ---------------------------------------------------------------------------


class FileVault:
    """Simple file-based credential vault.

    Stores encrypted blobs as files in a directory, one per user.
    Suitable for single-operator deployments. For production multi-tenant,
    swap in TheBrainVault or NeonVault.
    """

    def __init__(self, vault_dir: str) -> None:
        self._dir = vault_dir
        os.makedirs(vault_dir, exist_ok=True)

    def _path_for(self, user_id: str) -> str:
        # Sanitize user_id to a safe filename
        safe = base64.urlsafe_b64encode(user_id.encode()).decode()
        return os.path.join(self._dir, f"{safe}.json")

    async def store(self, user_id: str, encrypted_blob: str) -> None:
        """Store an encrypted credential blob for a user."""
        path = self._path_for(user_id)
        with open(path, "w") as f:
            f.write(encrypted_blob)

    async def fetch(self, user_id: str) -> str:
        """Fetch the encrypted credential blob for a user.

        Raises CredentialNotFoundError if no credentials are stored.
        """
        path = self._path_for(user_id)
        if not os.path.exists(path):
            raise CredentialNotFoundError(
                "No credentials found. Use register_credentials first."
            )
        with open(path) as f:
            return f.read()
