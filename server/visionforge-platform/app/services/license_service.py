from __future__ import annotations
import base64
import datetime as dt
import json
import os
import secrets
import stat
from pathlib import Path
from typing import Optional
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from app.config import config

PRODUCT_ID = "VISIONFORGE"
LICENSE_PREFIX = "VFG-"
PLAN_DAYS = {"day": 1, "week": 7, "month": 31, "permanent": None}
RSA_KEY_SIZE = 2048
RSA_BYTES = 256

_KEY_SALT = b"VFG_LICENSE_KEY_V1_PLATFORM"
_KEY_INFO = b"vfg_platform_private_key_encryption"
_MAX_ENCRYPTED_KEY_FILE_BYTES = 64 * 1024


def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode("ascii").rstrip("=")


def _b64u_decode(s: str) -> bytes:
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s.encode("ascii"))


def canonical(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _derive_encryption_key() -> bytes:
    password = config.PRIVATE_KEY_PASSWORD
    if not password:
        raise RuntimeError("PRIVATE_KEY_PASSWORD not configured — cannot encrypt/decrypt private key")
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=_KEY_SALT, info=_KEY_INFO)
    return hkdf.derive(password.encode("utf-8"))


def _get_encrypted_key_path() -> Path:
    return Path(config.PRIVATE_KEY_PATH).with_suffix(".pem.enc")


def _private_key_open_flags() -> int:
    """Return flags that prevent following the final path component where supported."""
    return os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)


def _validate_private_key_file_stat(file_stat: os.stat_result, path: Path) -> None:
    """Reject unsafe encrypted-key files before their contents enter this process."""
    if not stat.S_ISREG(file_stat.st_mode):
        raise ValueError(f"Encrypted private key must be a regular file: {path}")
    if file_stat.st_nlink != 1:
        raise ValueError(f"Encrypted private key must not have multiple hard links: {path}")
    if file_stat.st_size > _MAX_ENCRYPTED_KEY_FILE_BYTES:
        raise ValueError(f"Encrypted private key file is too large: {path}")
    if os.name != "nt":
        if file_stat.st_uid != os.geteuid():
            raise PermissionError(f"Encrypted private key owner is invalid: {path}")
        if stat.S_IMODE(file_stat.st_mode) & 0o077:
            raise PermissionError(f"Encrypted private key permissions are too broad: {path}")


def _read_encrypted_private_key(path: Path) -> bytes:
    """Read the encrypted key through a no-follow descriptor and validate it twice.

    ``lstat`` detects symlinks before open; descriptor-level ``fstat`` and identity
    comparison make a replacement between validation and open fail closed.
    """
    try:
        before_open = os.lstat(path)
    except FileNotFoundError:
        raise FileNotFoundError(
            f"Private key not found at {path}. "
            "Run: python -c 'from app.services.license_service import init_platform_keys; init_platform_keys()'"
        ) from None
    if stat.S_ISLNK(before_open.st_mode):
        raise ValueError(f"Encrypted private key must not be a symlink: {path}")
    _validate_private_key_file_stat(before_open, path)

    try:
        descriptor = os.open(path, _private_key_open_flags())
    except OSError as exc:
        # Platforms without O_NOFOLLOW still receive the descriptor identity check.
        if getattr(exc, "errno", None) in {getattr(os, "ELOOP", 40), 40}:
            raise ValueError(f"Encrypted private key must not be a symlink: {path}") from exc
        raise
    try:
        opened_stat = os.fstat(descriptor)
        _validate_private_key_file_stat(opened_stat, path)
        if (before_open.st_dev, before_open.st_ino) != (opened_stat.st_dev, opened_stat.st_ino):
            raise ValueError(f"Encrypted private key changed while opening: {path}")
        with os.fdopen(descriptor, "rb", closefd=False) as key_file:
            blob = key_file.read(_MAX_ENCRYPTED_KEY_FILE_BYTES + 1)
        if len(blob) > _MAX_ENCRYPTED_KEY_FILE_BYTES:
            raise ValueError(f"Encrypted private key file is too large: {path}")
        return blob
    finally:
        os.close(descriptor)


def init_platform_keys() -> None:
    """Generate a new RSA-2048 keypair for the platform. Called once during setup."""
    key_path = Path(config.PRIVATE_KEY_PATH)
    enc_path = _get_encrypted_key_path()
    key_path.parent.mkdir(parents=True, exist_ok=True)

    if os.path.lexists(enc_path):
        raise FileExistsError(f"Encrypted private key already exists and will not be overwritten: {enc_path}")

    key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
    pem_data = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    aes_key = _derive_encryption_key()
    nonce = os.urandom(12)
    aesgcm = AESGCM(aes_key)
    ciphertext = aesgcm.encrypt(nonce, pem_data, None)
    encrypted_blob = b"VFP1" + nonce + ciphertext
    create_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(enc_path, create_flags, 0o600)
    except FileExistsError:
        raise FileExistsError(
            f"Encrypted private key already exists and will not be overwritten: {enc_path}"
        ) from None
    try:
        if os.name != "nt":
            os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=False) as key_file:
            key_file.write(encrypted_blob)
            key_file.flush()
            os.fsync(descriptor)
    finally:
        os.close(descriptor)

    pub = key.public_key().public_numbers()
    print(f"[OK] Encrypted private key saved to: {enc_path}")
    print(f"[INFO] Public key N (first 40 chars): {str(pub.n)[:40]}...")
    print(f"[INFO] Public key E: {pub.e}")


_cached_private_key: RSAPrivateKey | None = None
_cached_public_key: rsa.RSAPublicKey | None = None
_cache_lock = __import__("threading").Lock()


def load_private_key() -> RSAPrivateKey:
    """Load and decrypt the RSA private key. Cached in memory after first load."""
    global _cached_private_key
    if _cached_private_key is not None:
        return _cached_private_key
    with _cache_lock:
        if _cached_private_key is not None:
            return _cached_private_key
        enc_path = _get_encrypted_key_path()
        blob = _read_encrypted_private_key(enc_path)
        if blob[:4] != b"VFP1":
            raise ValueError("Invalid encrypted key file format")
        nonce = blob[4:16]
        ciphertext = blob[16:]
        aes_key = _derive_encryption_key()
        aesgcm = AESGCM(aes_key)
        try:
            pem_data = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception:
            raise ValueError("Failed to decrypt private key — wrong password or corrupted file")
        key = serialization.load_pem_private_key(pem_data, password=None)
        if not isinstance(key, RSAPrivateKey):
            raise ValueError(f"Expected RSA private key, got {type(key).__name__}")
        _cached_private_key = key
        _cached_public_key = key.public_key()
        return key


def load_public_key() -> rsa.RSAPublicKey:
    """Load RSA public key (for verification). Uses cache."""
    global _cached_public_key
    if _cached_public_key is not None:
        return _cached_public_key
    key = load_private_key()  # load once, also caches public
    return key.public_key()


def make_payload(plan: str, hwid_hash: Optional[str], features: list[str] | None = None) -> dict:
    """Construct a license payload matching VisionForge's offline_license.py format exactly."""
    now = dt.datetime.now(dt.timezone.utc)
    days = PLAN_DAYS.get(plan)
    if days is None:
        expires = "permanent"
    else:
        expires = (now + dt.timedelta(days=days)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    feat_list = [str(f).strip() for f in (features or []) if str(f).strip()] or ["aim"]
    return {
        "v": 1,
        "product": PRODUCT_ID,
        "license_id": secrets.token_hex(8).upper(),
        "plan": plan,
        "issued_at": now.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "expires_at": expires,
        "hwid_hash": (hwid_hash or "").strip().upper() if hwid_hash else "",
        "note": "",
        "features": feat_list,
    }


def sign_payload(payload: dict) -> str:
    """Sign a license payload and return the full key string VFG-<payload>.<sig>"""
    key = load_private_key()
    sig = key.sign(canonical(payload), padding.PKCS1v15(), hashes.SHA256())
    return LICENSE_PREFIX + b64u(canonical(payload)) + "." + b64u(sig)


def generate_license_key(plan: str, features: list[str] | None = None) -> tuple[str, dict]:
    """Generate a new unbound license key. Returns (key_text, payload_dict)."""
    payload = make_payload(plan, hwid_hash=None, features=features)
    key_text = sign_payload(payload)
    return key_text, payload


def verify_key_text(key_text: str) -> dict | None:
    """Parse and verify a key string. Returns payload dict or None."""
    try:
        s = key_text.strip()
        for prefix in ("VFG-", "V28-", "V27-"):
            if s.startswith(prefix):
                s = s[len(prefix):]
                break
        if "." not in s:
            return None
        p_b64, sig_b64 = s.split(".", 1)
        payload_bytes = _b64u_decode(p_b64)
        sig = _b64u_decode(sig_b64)
        payload = json.loads(payload_bytes.decode("utf-8"))
        if not isinstance(payload, dict):
            return None
        pub_key = load_public_key()
        pub_key.verify(sig, canonical(payload), padding.PKCS1v15(), hashes.SHA256())
        return payload
    except Exception:
        return None
