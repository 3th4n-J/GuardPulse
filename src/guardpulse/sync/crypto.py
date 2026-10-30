"""End-to-end encryption for synced snapshots.

The sync key is 32 random bytes that only ever lives on paired phones
(``<data>/sync.key``). Firestore stores ``nonce || AES-256-GCM(json)``; GCM also
authenticates, so a snapshot edited in the cloud fails to open. The Firebase
account id is bound in as associated data, so a snapshot can't be replayed
into another account either.
"""

from __future__ import annotations

import base64
import json
import os
import zlib
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_FILE = "sync.key"
PAIR_PREFIX = "guardpulse-pair:1:"
_AAD = b"guardpulse-sync-v1|"


class SyncCryptoError(ValueError):
    pass


def new_key() -> bytes:
    return AESGCM.generate_key(bit_length=256)


def load_key(folder: Path) -> bytes | None:
    path = folder / KEY_FILE
    if not path.exists():
        return None
    key = path.read_bytes()
    return key if len(key) == 32 else None


def save_key(folder: Path, key: bytes) -> None:
    if len(key) != 32:
        raise SyncCryptoError("A sync key is 32 bytes.")
    (folder / KEY_FILE).write_bytes(key)


def forget_key(folder: Path) -> None:
    (folder / KEY_FILE).unlink(missing_ok=True)


def seal(key: bytes, uid: str, state: dict) -> str:
    """Compress + encrypt a snapshot for Firestore (base64 text)."""
    plain = zlib.compress(json.dumps(state, sort_keys=True, separators=(",", ":")).encode(), 9)
    nonce = os.urandom(12)
    sealed = AESGCM(key).encrypt(nonce, plain, _AAD + uid.encode())
    return base64.b64encode(nonce + sealed).decode()


def open_(key: bytes, uid: str, blob: str) -> dict:
    """Decrypt a snapshot. Raises SyncCryptoError if it's tampered or the key is wrong."""
    try:
        raw = base64.b64decode(blob)
        plain = AESGCM(key).decrypt(raw[:12], raw[12:], _AAD + uid.encode())
        return json.loads(zlib.decompress(plain))
    except (InvalidTag, ValueError, zlib.error) as exc:
        raise SyncCryptoError("This phone's sync key doesn't open the synced data.") from exc


def pair_code(uid: str, key: bytes) -> str:
    """What the pairing QR holds: the account id (to catch wrong-account scans) + the key."""
    return PAIR_PREFIX + uid + ":" + base64.urlsafe_b64encode(key).decode().rstrip("=")


def parse_pair_code(code: str) -> tuple[str, bytes]:
    code = (code or "").strip()
    if not code.startswith(PAIR_PREFIX):
        raise SyncCryptoError("That isn't a GuardPulse pairing code.")
    uid, _, encoded = code[len(PAIR_PREFIX):].rpartition(":")
    try:
        key = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except ValueError as exc:
        raise SyncCryptoError("That pairing code is damaged.") from exc
    if not uid or len(key) != 32:
        raise SyncCryptoError("That pairing code is damaged.")
    return uid, key
