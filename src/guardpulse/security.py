"""Cryptographic helpers: partner PIN hashing, TOTP codes and integrity seals.

Nothing here stores a PIN or TOTP secret in a reversible form except the TOTP
secret itself, which must be reversible to compute codes. The partner is the
only person who ever sees it (as a QR code during set-up).
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import struct
import time
from pathlib import Path
from urllib.parse import quote

# scrypt cost: ~50 ms on a mid-range phone, so brute-forcing a 6-digit PIN
# from a copied database still takes hours, and the lockout stops it on-device.
SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1
PIN_MIN_LENGTH = 4
PIN_MAX_LENGTH = 12

TOTP_DIGITS = 6
TOTP_PERIOD = 30
TOTP_WINDOW = 1  # accept one step either side for clock drift


class WeakPin(ValueError):
    pass


def validate_pin(pin: str) -> str:
    pin = (pin or "").strip()
    if not pin.isdigit() or not PIN_MIN_LENGTH <= len(pin) <= PIN_MAX_LENGTH:
        raise WeakPin(f"PIN must be {PIN_MIN_LENGTH}-{PIN_MAX_LENGTH} digits.")
    if len(set(pin)) == 1:
        raise WeakPin("PIN can't be the same digit repeated.")
    if pin in "01234567890123456789" or pin in "98765432109876543210":
        raise WeakPin("PIN can't be a straight sequence.")
    return pin


def hash_pin(pin: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    digest = hashlib.scrypt(
        pin.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32
    )
    return "scrypt${}${}${}${}${}".format(
        SCRYPT_N, SCRYPT_R, SCRYPT_P, salt.hex(), digest.hex()
    )


def verify_pin(pin: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_hex, digest_hex = stored.split("$")
    except ValueError:
        return False
    if scheme != "scrypt":
        return False
    digest = hashlib.scrypt(
        (pin or "").encode(),
        salt=bytes.fromhex(salt_hex),
        n=int(n),
        r=int(r),
        p=int(p),
        dklen=len(digest_hex) // 2,
    )
    return hmac.compare_digest(digest.hex(), digest_hex)


# The Kotlin settings-guard runs while the Flet app is closed and has no scrypt,
# so the PIN is also written as a PBKDF2-HMAC-SHA256 hash the native layer can
# verify with javax.crypto. The file is HMAC-sealed, so editing it is detected.
PBKDF2_ITERATIONS = 200_000


def pbkdf2_hash(pin: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", pin.encode(), salt, PBKDF2_ITERATIONS, dklen=32)
    return f"pbkdf2${PBKDF2_ITERATIONS}${salt.hex()}${digest.hex()}"


def verify_pbkdf2(pin: str, stored: str) -> bool:
    try:
        scheme, iters, salt_hex, digest_hex = stored.split("$")
    except ValueError:
        return False
    if scheme != "pbkdf2":
        return False
    digest = hashlib.pbkdf2_hmac(
        "sha256", (pin or "").encode(), bytes.fromhex(salt_hex), int(iters), dklen=len(digest_hex) // 2
    )
    return hmac.compare_digest(digest.hex(), digest_hex)


def lockout_seconds(failed_attempts: int) -> int:
    """Back-off after repeated wrong PINs/codes: 3 free tries, then 30 s doubling to 1 h."""
    if failed_attempts < 3:
        return 0
    return min(30 * 2 ** (failed_attempts - 3), 3600)


# --- TOTP (RFC 6238) -------------------------------------------------------


def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _hotp(secret: str, counter: int) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    code = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(code % 10**TOTP_DIGITS).zfill(TOTP_DIGITS)


def totp_now(secret: str, at: float | None = None) -> str:
    return _hotp(secret, int((time.time() if at is None else at) // TOTP_PERIOD))


def verify_totp(secret: str, code: str, last_counter: int, at: float | None = None) -> int | None:
    """Return the matched time-step counter, or ``None``.

    Steps at or before ``last_counter`` are rejected so a code can't be reused.
    """
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit() or len(code) != TOTP_DIGITS:
        return None
    now = int((time.time() if at is None else at) // TOTP_PERIOD)
    for counter in range(now - TOTP_WINDOW, now + TOTP_WINDOW + 1):
        if counter > last_counter and hmac.compare_digest(_hotp(secret, counter), code):
            return counter
    return None


def totp_uri(secret: str, account: str, issuer: str = "GuardPulse") -> str:
    label = quote(f"{issuer}:{account}")
    return (
        f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer)}"
        f"&digits={TOTP_DIGITS}&period={TOTP_PERIOD}"
    )


# --- Integrity seal --------------------------------------------------------


class KeyProvider:
    """Source of the HMAC key used to seal the rule set.

    ``FileKeyProvider`` keeps the key in app-private storage next to the DB.
    The Android build will swap in a Keystore-backed provider (native bridge)
    so the key can't be lifted off the device with the database.
    """

    def get_key(self) -> bytes:  # pragma: no cover - interface
        raise NotImplementedError


class FileKeyProvider(KeyProvider):
    def __init__(self, path: Path):
        self.path = path

    def get_key(self) -> bytes:
        if self.path.exists():
            return self.path.read_bytes()
        key = secrets.token_bytes(32)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_bytes(key)
        return key


def seal(key: bytes, payload: bytes) -> str:
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def seal_ok(key: bytes, payload: bytes, expected: str) -> bool:
    return hmac.compare_digest(seal(key, payload), expected or "")
