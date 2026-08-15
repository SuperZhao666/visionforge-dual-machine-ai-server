"""Payment-channel catalog and protocol normalization."""
from __future__ import annotations

from dataclasses import dataclass


PAYMENT_METHOD_WECHAT = "wechat"
PAYMENT_METHOD_ALIPAY = "alipay"
DEFAULT_PAYMENT_METHOD = PAYMENT_METHOD_WECHAT


@dataclass(frozen=True)
class PaymentChannel:
    key: str
    label: str
    vmq_type: str
    storage_aliases: tuple[str, ...]


PAYMENT_CHANNELS = (
    PaymentChannel(PAYMENT_METHOD_WECHAT, "微信支付", "1", ("wechat", "vmq", "wx", "weixin", "1")),
    PaymentChannel(PAYMENT_METHOD_ALIPAY, "支付宝", "2", ("alipay", "zfb", "2")),
)
PAYMENT_CHANNEL_BY_KEY = {channel.key: channel for channel in PAYMENT_CHANNELS}
PAYMENT_METHOD_ALIASES = {
    alias: channel.key
    for channel in PAYMENT_CHANNELS
    for alias in channel.storage_aliases
}
VMQ_TYPE_TO_PAYMENT_METHOD = {channel.vmq_type: channel.key for channel in PAYMENT_CHANNELS}


def normalize_payment_method(value: object, *, default: str = "") -> str:
    normalized = str(value or "").strip().lower()
    if not normalized:
        normalized = str(default or "").strip().lower()
    return PAYMENT_METHOD_ALIASES.get(normalized, "")


def payment_method_label(value: object) -> str:
    method = normalize_payment_method(value)
    channel = PAYMENT_CHANNEL_BY_KEY.get(method)
    return channel.label if channel else str(value or "").strip()


def payment_method_storage_aliases(value: object) -> tuple[str, ...]:
    method = normalize_payment_method(value)
    channel = PAYMENT_CHANNEL_BY_KEY.get(method)
    return channel.storage_aliases if channel else ()


def payment_method_from_vmq_type(value: object) -> str:
    normalized = str(value or "").strip() or "1"
    return VMQ_TYPE_TO_PAYMENT_METHOD.get(normalized, "")


def supported_payment_method_keys() -> tuple[str, ...]:
    return tuple(channel.key for channel in PAYMENT_CHANNELS)
