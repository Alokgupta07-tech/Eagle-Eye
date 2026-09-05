"""Credential protection at rest (v2.4 step 11).
With `cryptography` importable AND SENTINEL_SECRET set, target auth headers are Fernet-
encrypted before storage ("enc:" prefix) and decrypted only when a target is called.
Otherwise values are stored as-is and a one-line warning is printed at boot."""
from __future__ import annotations

import base64
import hashlib

_PREFIX = "enc:"


def _fernet(secret: str):
    try:
        from cryptography.fernet import Fernet  # type: ignore
    except Exception:  # noqa: BLE001
        return None
    key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())
    return Fernet(key)


def available(secret: str) -> bool:
    return bool(secret) and _fernet(secret) is not None


def protect(value: str | None, secret: str) -> str | None:
    if not value or value.startswith(_PREFIX):
        return value
    f = _fernet(secret) if secret else None
    if not f:
        return value
    return _PREFIX + f.encrypt(value.encode()).decode()


def reveal(value: str | None, secret: str) -> str | None:
    if not value or not value.startswith(_PREFIX):
        return value
    f = _fernet(secret) if secret else None
    if not f:
        raise RuntimeError("auth_header is encrypted but SENTINEL_SECRET/cryptography unavailable")
    return f.decrypt(value[len(_PREFIX):].encode()).decode()


def mask(value: str | None) -> str | None:
    """`Bearer abcdef…wxyz` -> `Bearer ****wxyz`; never returns the secret."""
    if not value:
        return value
    if value.startswith(_PREFIX):
        return "****(encrypted)"
    scheme, _, rest = value.partition(" ")
    tok = rest or scheme
    tail = tok[-4:] if len(tok) > 8 else ""
    return (f"{scheme} ****{tail}" if rest else f"****{tail}").strip()
