"""API-key store. Keys are random 256-bit secrets, stored only as salted SHA-256 hashes.

Token format: ``mcph_<id>_<secret>``. The id is public and selects the record; the secret is
shown once at creation and never stored. File changes, including revocation, are picked up
without a restart.
"""

from __future__ import annotations

import contextlib
import hashlib
import hmac
import json
import os
import re
import secrets
import tempfile
import threading
import time
from pathlib import Path

from pydantic import BaseModel, Field

from mcp_hub.errors import ConfigError, ValidationFailed

PREFIX = "mcph"
_SCOPE_RE = re.compile(r"^(\*|[a-z0-9_]+:[a-z0-9_*]+)$")


class KeyRecord(BaseModel):
    id: str
    label: str = Field(max_length=100)
    salt: str
    hash: str
    scopes: list[str]
    created_at: int
    expires_at: int | None = None
    revoked: bool = False


def _digest(salt_hex: str, secret: str) -> str:
    return hashlib.sha256(bytes.fromhex(salt_hex) + secret.encode()).hexdigest()


def validate_scopes(scopes: list[str]) -> list[str]:
    if not scopes:
        raise ValidationFailed("At least one scope is required.")
    for s in scopes:
        if not _SCOPE_RE.match(s):
            raise ValidationFailed(f"Invalid scope: {s!r}")
    return sorted(set(scopes))


class KeyStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        self._records: dict[str, KeyRecord] = {}
        self._mtime_ns = -1

    def _load_locked(self) -> None:
        try:
            st = self.path.stat()
        except FileNotFoundError:
            self._records, self._mtime_ns = {}, -1
            return
        if st.st_mtime_ns == self._mtime_ns:
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            records = [KeyRecord.model_validate(r) for r in raw["keys"]]
        except (OSError, ValueError, KeyError, TypeError) as exc:
            raise ConfigError(f"API key file is unreadable or corrupt: {self.path}") from exc
        self._records = {r.id: r for r in records}
        self._mtime_ns = st.st_mtime_ns

    def _save_locked(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps({"keys": [r.model_dump() for r in self._records.values()]}, indent=2)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".keys-", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(payload)
            with contextlib.suppress(OSError):  # best effort on Windows
                os.chmod(tmp, 0o600)
            os.replace(tmp, self.path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp)
            raise
        self._mtime_ns = self.path.stat().st_mtime_ns

    def create(
        self, label: str, scopes: list[str], expires_days: float | None = None
    ) -> tuple[str, KeyRecord]:
        scopes = validate_scopes(scopes)
        with self._lock:
            self._load_locked()
            key_id = secrets.token_hex(4)
            while key_id in self._records:  # pragma: no cover - 2^32 space
                key_id = secrets.token_hex(4)
            secret = secrets.token_urlsafe(32)
            salt = secrets.token_hex(16)
            now = int(time.time())
            rec = KeyRecord(
                id=key_id,
                label=label,
                salt=salt,
                hash=_digest(salt, secret),
                scopes=scopes,
                created_at=now,
                expires_at=int(now + expires_days * 86400) if expires_days else None,
            )
            self._records[key_id] = rec
            self._save_locked()
        return f"{PREFIX}_{key_id}_{secret}", rec

    def revoke(self, key_id: str) -> bool:
        with self._lock:
            self._load_locked()
            rec = self._records.get(key_id)
            if rec is None:
                return False
            rec.revoked = True
            self._save_locked()
            return True

    def list(self) -> list[KeyRecord]:
        with self._lock:
            self._load_locked()
            return list(self._records.values())

    def verify(self, token: str) -> tuple[KeyRecord | None, str]:
        """Return (record, "ok") or (None, reason). Reasons: malformed, unknown_key, bad_secret,
        revoked, expired."""
        parts = token.split("_", 2)
        if len(parts) != 3 or parts[0] != PREFIX or not parts[1] or not parts[2]:
            return None, "malformed"
        _, key_id, secret = parts
        with self._lock:
            try:
                self._load_locked()
            except ConfigError:
                return None, "store_error"  # fail closed
            rec = self._records.get(key_id)
        if rec is None:
            _digest("00" * 16, secret)  # equalise timing with the found-record path
            return None, "unknown_key"
        if not hmac.compare_digest(_digest(rec.salt, secret), rec.hash):
            return None, "bad_secret"
        if rec.revoked:
            return None, "revoked"
        if rec.expires_at is not None and rec.expires_at <= time.time():
            return None, "expired"
        return rec, "ok"
