"""Reusable client-side crypto helpers for encrypted browser profiles."""
# Encrypts profile data and creates stable IDs for entries.

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import secrets
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


PASSWORD_ITERATIONS = 210_000
ENC_PREFIX = "enc:v2:"
WRAP_KDF_VERSION = f"pbkdf2-sha256:{PASSWORD_ITERATIONS}"
PROFILE_SCHEMA_VERSION = "browser-profile-v1"


class ProfileCryptoError(RuntimeError):
    """Raised when encrypted profile data cannot be encoded or decoded."""


def derive_password_key(password: str, salt_hex: str) -> bytes:
    # Derives the wrapping key from the account password.
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        bytes.fromhex(salt_hex),
        PASSWORD_ITERATIONS,
        dklen=32,
    )


def new_salt_hex() -> str:
    return secrets.token_hex(16)


def encrypt_json(value: Any, key: bytes) -> str:
    # Serializes and encrypts one JSON payload.
    nonce = secrets.token_bytes(12)
    plaintext = json.dumps(value, separators=(",", ":")).encode("utf-8")
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    combined = nonce + ciphertext
    tag = hmac.new(key, combined, "sha256").digest()
    packed = base64.urlsafe_b64encode(combined + tag).decode("ascii")
    return f"{ENC_PREFIX}{packed}"


def decrypt_json(packed: str, key: bytes) -> Any:
    # Verifies integrity before decrypting encrypted payloads.
    if not packed.startswith(ENC_PREFIX):
        return json.loads(packed)
    raw = base64.urlsafe_b64decode(packed[len(ENC_PREFIX):].encode("ascii"))
    if len(raw) < 12 + 32:
        raise ProfileCryptoError("Encrypted value is corrupt.")
    combined = raw[:-32]
    expected_tag = raw[-32:]
    actual_tag = hmac.new(key, combined, "sha256").digest()
    if not hmac.compare_digest(actual_tag, expected_tag):
        raise ProfileCryptoError("Encrypted value failed integrity check.")
    nonce = combined[:12]
    ciphertext = combined[12:]
    aesgcm = AESGCM(key)
    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    except Exception as exc:  # pragma: no cover - cryptography raises backend-specific errors
        raise ProfileCryptoError("Encrypted value could not be decrypted.") from exc
    return json.loads(plaintext.decode("utf-8"))


def wrap_profile_key(master_key: bytes, password: str) -> dict[str, str]:
    # Protects the profile master key with the user's password.
    salt_hex = new_salt_hex()
    password_key = derive_password_key(password, salt_hex)
    payload = {"master_key": base64.urlsafe_b64encode(master_key).decode("ascii")}
    return {
        "wrapped_profile_key": encrypt_json(payload, password_key),
        "wrap_salt": salt_hex,
        "wrap_kdf_version": WRAP_KDF_VERSION,
        "profile_schema_version": PROFILE_SCHEMA_VERSION,
    }


def unwrap_profile_key(record: dict[str, Any], password: str) -> bytes:
    salt_hex = str(record.get("wrap_salt", "")).strip()
    wrapped = str(record.get("wrapped_profile_key", "")).strip()
    if not salt_hex or not wrapped:
        raise ProfileCryptoError("Profile key record is incomplete.")
    payload = decrypt_json(wrapped, derive_password_key(password, salt_hex))
    if not isinstance(payload, dict) or "master_key" not in payload:
        raise ProfileCryptoError("Profile key payload is invalid.")
    try:
        return base64.urlsafe_b64decode(str(payload["master_key"]).encode("ascii"))
    except Exception as exc:
        raise ProfileCryptoError("Profile key payload is corrupt.") from exc


def wrap_local_profile_key(master_key: bytes, device_key: bytes) -> str:
    payload = {"master_key": base64.urlsafe_b64encode(master_key).decode("ascii")}
    return encrypt_json(payload, device_key)


def unwrap_local_profile_key(packed: str, device_key: bytes) -> bytes:
    payload = decrypt_json(packed, device_key)
    if not isinstance(payload, dict) or "master_key" not in payload:
        raise ProfileCryptoError("Local profile key payload is invalid.")
    try:
        return base64.urlsafe_b64decode(str(payload["master_key"]).encode("ascii"))
    except Exception as exc:
        raise ProfileCryptoError("Local profile key payload is corrupt.") from exc


def deterministic_entry_id(master_key: bytes, collection: str, stable_id: str) -> str:
    # Hides stable IDs while keeping sync IDs deterministic.
    digest = hmac.new(
        master_key,
        f"{collection}:{stable_id}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    return digest[:32]
