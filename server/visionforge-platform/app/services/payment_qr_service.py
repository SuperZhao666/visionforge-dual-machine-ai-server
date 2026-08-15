"""Validated storage for administrator-provided fixed-amount payment QR images."""
from __future__ import annotations

import os
import re
import secrets
import zlib
from pathlib import Path

from app.services.payment_channels import normalize_payment_method


MAX_PAYMENT_QR_BYTES = 3 * 1024 * 1024
MIN_PAYMENT_QR_PIXELS = 128
MAX_PAYMENT_QR_PIXELS = 4096
PAYMENT_QR_FILE_MODE = 0o640
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
SAFE_PLAN_KEY_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,31}$")
PAYMENT_QR_DIRECTORY = Path(__file__).resolve().parents[1] / "static" / "img"


def payment_qr_filename(plan_key: object, payment_method: object) -> str:
    safe_plan_key = str(plan_key or "").strip().lower()
    method = normalize_payment_method(payment_method)
    if not method:
        raise ValueError("unsupported payment method")
    if not SAFE_PLAN_KEY_RE.fullmatch(safe_plan_key):
        raise ValueError("invalid payment plan")
    return f"{method}_qr_{safe_plan_key}.png"


def payment_qr_path(plan_key: object, payment_method: object) -> Path:
    return PAYMENT_QR_DIRECTORY / payment_qr_filename(plan_key, payment_method)


def payment_qr_ready(plan_key: object, payment_method: object) -> bool:
    try:
        path = payment_qr_path(plan_key, payment_method)
        return path.is_file() and path.stat().st_size > len(PNG_SIGNATURE)
    except (OSError, ValueError):
        return False


def _set_payment_qr_file_permissions(path: Path) -> None:
    """Allow the web-server group to read a QR image without making it public."""
    if os.name != "nt":
        os.chmod(path, PAYMENT_QR_FILE_MODE)


def validate_payment_qr_png(content: bytes) -> tuple[int, int]:
    if not content:
        raise ValueError("请选择 PNG 二维码图片")
    if len(content) > MAX_PAYMENT_QR_BYTES:
        raise ValueError("二维码图片不能超过 3 MB")
    if len(content) < 45 or not content.startswith(PNG_SIGNATURE):
        raise ValueError("仅支持有效的 PNG 二维码图片")
    width = 0
    height = 0
    offset = len(PNG_SIGNATURE)
    seen_ihdr = False
    seen_idat = False
    seen_iend = False
    while offset + 12 <= len(content):
        chunk_length = int.from_bytes(content[offset:offset + 4], "big")
        chunk_end = offset + 12 + chunk_length
        if chunk_length > MAX_PAYMENT_QR_BYTES or chunk_end > len(content):
            raise ValueError("PNG 二维码图片结构损坏")
        chunk_type = content[offset + 4:offset + 8]
        chunk_data = content[offset + 8:offset + 8 + chunk_length]
        supplied_crc = int.from_bytes(content[offset + 8 + chunk_length:chunk_end], "big")
        expected_crc = zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF
        if supplied_crc != expected_crc:
            raise ValueError("PNG 二维码图片校验失败")
        if chunk_type == b"IHDR":
            if seen_ihdr or offset != len(PNG_SIGNATURE) or chunk_length != 13:
                raise ValueError("PNG 二维码图片头无效")
            seen_ihdr = True
            width = int.from_bytes(chunk_data[0:4], "big")
            height = int.from_bytes(chunk_data[4:8], "big")
        elif chunk_type == b"IDAT":
            seen_idat = True
        elif chunk_type == b"IEND":
            if chunk_length != 0 or chunk_end != len(content):
                raise ValueError("PNG 二维码图片结尾无效")
            seen_iend = True
            break
        offset = chunk_end
    if not (seen_ihdr and seen_idat and seen_iend):
        raise ValueError("PNG 二维码图片结构不完整")
    if not (MIN_PAYMENT_QR_PIXELS <= width <= MAX_PAYMENT_QR_PIXELS):
        raise ValueError("二维码图片宽度必须在 128 到 4096 像素之间")
    if not (MIN_PAYMENT_QR_PIXELS <= height <= MAX_PAYMENT_QR_PIXELS):
        raise ValueError("二维码图片高度必须在 128 到 4096 像素之间")
    return width, height


def save_payment_qr_png(plan_key: object, payment_method: object, content: bytes) -> dict[str, object]:
    width, height = validate_payment_qr_png(content)
    path = payment_qr_path(plan_key, payment_method)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    try:
        with temporary_path.open("xb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        _set_payment_qr_file_permissions(temporary_path)
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)
    return {
        "path": path,
        "filename": path.name,
        "width": width,
        "height": height,
        "size": len(content),
    }
