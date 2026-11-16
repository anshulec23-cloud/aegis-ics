"""Zero-touch device enrollment crypto (ADR 0006).

Key agreement:   shared = X25519(own_private, peer_public)        (RFC 7748, 32 bytes)
Key derivation:  PRK    = HMAC-SHA256(key=b"aegis-ics-v1", msg=shared)          (HKDF-Extract)
                 OKM    = HMAC-SHA256(key=PRK, msg=info || 0x01)                 (HKDF-Expand, 1 block)
                 info   = device_id (ASCII) || b"|" || device_pub (32 B) || host_pub (32 B)
HMAC key used on the wire = lowercase hex of OKM (64 ASCII characters), exactly like the
pre-shared keys of protocol v0, so one signing routine serves both.

Public keys travel as 64 lowercase hex characters (raw RFC 7748 little-endian encoding).
The same derivation runs in the host, the simulator and the ESP32 firmware
(firmware/esp32_slave_sensor, ``derive_session_key``). ``tests/security`` holds the
shared test vector.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from typing import Tuple

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

HKDF_SALT = b"aegis-ics-v1"
HOST_IDENTITY_FILE = "host_identity.key"


# ----------------------------------------------------------------- primitives ---


def generate_keypair() -> Tuple[X25519PrivateKey, str]:
    priv = X25519PrivateKey.generate()
    return priv, public_hex(priv)


def private_from_hex(hex_value: str) -> X25519PrivateKey:
    return X25519PrivateKey.from_private_bytes(bytes.fromhex(hex_value))


def private_to_hex(priv: X25519PrivateKey) -> str:
    return priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption()).hex()


def public_hex(priv: X25519PrivateKey) -> str:
    return priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def is_valid_public_hex(value: object) -> bool:
    if not isinstance(value, str) or len(value) != 64:
        return False
    try:
        X25519PublicKey.from_public_bytes(bytes.fromhex(value))
        return True
    except ValueError:
        return False


def derive_session_key(
    own_private: X25519PrivateKey,
    peer_public_hex: str,
    device_id: str,
    device_pub_hex: str,
    host_pub_hex: str,
) -> str:
    """Return the 64-hex-char HMAC key shared by a device and the host."""
    shared = own_private.exchange(X25519PublicKey.from_public_bytes(bytes.fromhex(peer_public_hex)))
    if shared == b"\x00" * 32:
        raise ValueError("low-order public key rejected")
    prk = hmac.new(HKDF_SALT, shared, hashlib.sha256).digest()
    info = (
        device_id.encode("ascii")
        + b"|"
        + bytes.fromhex(device_pub_hex)
        + bytes.fromhex(host_pub_hex)
    )
    okm = hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    return okm.hex()


def fingerprint(public_key_hex: str) -> str:
    """Short, human-comparable fingerprint (shown on the dashboard and the device console)."""
    digest = hashlib.sha256(bytes.fromhex(public_key_hex)).hexdigest().upper()
    return "-".join(digest[i : i + 4] for i in range(0, 12, 4))


# --------------------------------------------------------------- host identity ---


def load_or_create_host_identity(data_dir: str) -> X25519PrivateKey:
    """The host's long-term X25519 key, created on first start (file mode 0600)."""
    path = os.path.join(data_dir, HOST_IDENTITY_FILE)
    try:
        with open(path, "r", encoding="ascii") as fh:
            return private_from_hex(fh.read().strip())
    except FileNotFoundError:
        pass
    priv = X25519PrivateKey.generate()
    os.makedirs(data_dir, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as fh:
        fh.write(private_to_hex(priv))
    print(f"[Enrollment] Created host identity {fingerprint(public_hex(priv))} in {path}")
    return priv
