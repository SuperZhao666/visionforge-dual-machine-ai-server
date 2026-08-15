"""Private adapter from a Xianyu API card to VisionForge on-demand code issuance."""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer


HOST = "0.0.0.0"
PORT = 8080
MAX_RESPONSE_BYTES = 64 * 1024
ISSUE_PATH = "/api/integrations/code-issuances/issue"
PRODUCT_KEY_RE = re.compile(r"^[a-z0-9_-]{1,32}$")
DEFAULT_DELIVERY_TEMPLATE = (
    "【VisionForge 自动发货】\n"
    "商品：{product_name}\n"
    "兑换码：{code}\n"
    "下载：{download_url}\n"
    "使用：安装客户端 → 注册或登录 → 账户中心 → 兑换时长 → 输入兑换码。"
)
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("visionforge.code_issuance_bridge")


class BridgeHandler(BaseHTTPRequestHandler):
    server_version = "VisionForgeCodeIssuanceBridge/2"

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler contract
        parsed = urllib.parse.urlsplit(self.path)
        if parsed.path == "/health":
            self._write_json(200, {"ok": True})
            return
        if parsed.path != "/issue":
            self._write_json(404, {"ok": False, "error": "not_found"})
            return
        if not self._is_internal_request():
            self._write_json(401, {"ok": False, "error": "unauthorized"})
            return
        try:
            payload = _issuance_payload(urllib.parse.parse_qs(parsed.query, keep_blank_values=True))
            status, response = _post_to_platform(payload)
            status, response = _delivery_response(status, response)
        except BridgeError as exc:
            logger.warning("bridge request rejected error_code=%s", exc.error_code)
            self._write_json(exc.status_code, {"ok": False, "error": exc.error_code})
            return
        except Exception:
            logger.exception("bridge request failed without sensitive payload")
            self._write_json(502, {"ok": False, "error": "bridge_unavailable"})
            return
        trace_id = str(response.get("trace_id") or "")[:64] if isinstance(response, dict) else ""
        logger.info("platform code response status=%s trace_id=%s", status, trace_id)
        self._write_json(status, response)

    def log_message(self, _format: str, *_args) -> None:
        """Suppress access logs because the query string contains an external order identifier."""

    def _is_internal_request(self) -> bool:
        expected = os.environ.get("BRIDGE_INTERNAL_TOKEN", "")
        supplied = self.headers.get("Authorization", "")
        return bool(
            len(expected) >= 32
            and supplied.startswith("Bearer ")
            and hmac.compare_digest(expected, supplied[7:])
        )

    def _write_json(self, status: int, payload: object) -> None:
        body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(int(status))
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class BridgeError(ValueError):
    def __init__(self, error_code: str, status_code: int):
        super().__init__(error_code)
        self.error_code = error_code
        self.status_code = status_code


def _issuance_payload(query: dict[str, list[str]]) -> dict:
    product_key = _required_query(query, "product_key", 32).lower()
    if not PRODUCT_KEY_RE.fullmatch(product_key):
        raise BridgeError("invalid_request", 400)
    order_id = _required_query(query, "order_id", 160)
    unit_index = _unit_index(query)
    account = _required_env("XIANYU_PROVIDER_ACCOUNT", 120)
    return {
        "product_key": product_key,
        "request_id": _opaque_request_id(account, order_id, unit_index),
    }


def _opaque_request_id(account: str, order_id: str, unit_index: int) -> str:
    secret = _required_env("CODE_ISSUANCE_HMAC_SECRET", 500)
    if len(secret) < 32:
        raise BridgeError("bridge_not_configured", 503)
    root_key = hmac.new(
        secret.encode("utf-8"),
        b"visionforge:xianyu:idempotency:v1",
        hashlib.sha256,
    ).digest()
    canonical = "\n".join(("xianyu", account, order_id, str(unit_index)))
    digest = hmac.new(root_key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"xi1_{digest}"


def _post_to_platform(payload: dict) -> tuple[int, object]:
    endpoint = _platform_endpoint()
    service_id = _required_env("CODE_ISSUANCE_SERVICE_ID", 120)
    secret = _required_env("CODE_ISSUANCE_HMAC_SECRET", 500)
    if len(secret) < 32:
        raise BridgeError("bridge_not_configured", 503)
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    timestamp = str(int(time.time()))
    nonce = secrets.token_urlsafe(24)
    body_digest = hashlib.sha256(body).hexdigest()
    canonical = "\n".join(("POST", ISSUE_PATH, timestamp, nonce, body_digest))
    signature = hmac.new(secret.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    request = urllib.request.Request(
        endpoint,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "X-VF-Service": service_id,
            "X-VF-Timestamp": timestamp,
            "X-VF-Nonce": nonce,
            "X-VF-Signature": signature,
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            status = int(response.status)
            raw = response.read(MAX_RESPONSE_BYTES)
    except urllib.error.HTTPError as exc:
        status = int(exc.code)
        raw = exc.read(MAX_RESPONSE_BYTES)
    except urllib.error.URLError as exc:
        raise BridgeError("platform_unavailable", 502) from exc
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BridgeError("platform_response_invalid", 502) from exc
    return status, parsed


def _delivery_response(status: int, response: object) -> tuple[int, object]:
    if status != 200:
        return status, response
    if not isinstance(response, dict) or not response.get("ok") or not isinstance(response.get("data"), dict):
        raise BridgeError("platform_response_invalid", 502)
    data = response["data"]
    product_name = _response_text(data, "product_name", 80)
    code = _response_text(data, "redemption_code", 100)
    download_url = _response_text(data, "download_url", 500)
    content = _delivery_template()
    for marker, value in {
        "{product_name}": product_name,
        "{code}": code,
        "{download_url}": download_url,
    }.items():
        content = content.replace(marker, value)
    return 200, {
        "ok": True,
        "data": content,
        "issuance_id": response.get("issuance_id"),
        "trace_id": str(response.get("trace_id") or "")[:64],
        "duplicate": bool(response.get("duplicate")),
    }


def _delivery_template() -> str:
    template = str(os.environ.get("DELIVERY_MESSAGE_TEMPLATE") or DEFAULT_DELIVERY_TEMPLATE)
    template = template.replace("\\n", "\n")[:4000]
    if any(marker not in template for marker in ("{product_name}", "{code}", "{download_url}")):
        raise BridgeError("bridge_not_configured", 503)
    return template


def _platform_endpoint() -> str:
    endpoint = str(
        os.environ.get("PLATFORM_CODE_ISSUANCE_URL") or ""
    ).strip()
    if not endpoint.startswith("https://") or not endpoint.endswith(ISSUE_PATH) or len(endpoint) > 1000:
        raise BridgeError("platform_url_invalid", 503)
    return endpoint


def _unit_index(query: dict[str, list[str]]) -> int:
    value = _optional_query(query, "unit_index", 3) or "1"
    try:
        unit_index = int(value)
    except ValueError as exc:
        raise BridgeError("invalid_request", 400) from exc
    if unit_index != 1:
        raise BridgeError("quantity_unsupported", 400)
    return unit_index


def _response_text(data: dict, field: str, max_length: int) -> str:
    value = str(data.get(field) or "").strip()
    if not value or len(value) > max_length:
        raise BridgeError("platform_response_invalid", 502)
    return value


def _required_env(name: str, max_length: int) -> str:
    value = str(os.environ.get(name, "")).strip()
    lowered = value.lower()
    placeholder_markers = (
        "replace-with",
        "replace_with",
        "placeholder",
        "change-me",
        "changeme",
    )
    if (
        not value
        or len(value) > max_length
        or any(marker in lowered for marker in placeholder_markers)
    ):
        raise BridgeError("bridge_not_configured", 503)
    return value


def _validate_runtime_configuration() -> None:
    bridge_token = _required_env("BRIDGE_INTERNAL_TOKEN", 500)
    issuance_secret = _required_env("CODE_ISSUANCE_HMAC_SECRET", 500)
    if len(bridge_token) < 32 or len(issuance_secret) < 32:
        raise BridgeError("bridge_not_configured", 503)
    _required_env("XIANYU_PROVIDER_ACCOUNT", 120)
    _required_env("CODE_ISSUANCE_SERVICE_ID", 120)
    _platform_endpoint()
    _delivery_template()


def _required_query(query: dict[str, list[str]], name: str, max_length: int) -> str:
    value = _optional_query(query, name, max_length)
    if not value:
        raise BridgeError("invalid_request", 400)
    return value


def _optional_query(query: dict[str, list[str]], name: str, max_length: int) -> str:
    values = query.get(name) or []
    if len(values) > 1:
        raise BridgeError("invalid_request", 400)
    value = str(values[0] if values else "").strip()
    if len(value) > max_length:
        raise BridgeError("invalid_request", 400)
    return value


if __name__ == "__main__":
    _validate_runtime_configuration()
    logger.info("code issuance bridge started")
    HTTPServer((HOST, PORT), BridgeHandler).serve_forever()
