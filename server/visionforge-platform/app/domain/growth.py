"""Enums for redemption, referral, and time-credit state machines."""
from enum import Enum


class ValueStrEnum(str, Enum):
    """Python 3.10-compatible string enum with StrEnum value semantics."""

    def __str__(self) -> str:
        return self.value


class RedemptionCodeStatus(ValueStrEnum):
    ISSUED = "issued"
    REDEEMED = "redeemed"
    REVOKED = "revoked"
    EXPIRED = "expired"


class IssuanceBatchStatus(ValueStrEnum):
    ACTIVE = "active"
    REVOKED = "revoked"


class ReferralStatus(ValueStrEnum):
    REGISTERED = "registered"
    REWARDED = "rewarded"


class TimeCreditSource(ValueStrEnum):
    WELCOME = "welcome"
    REDEMPTION = "redemption"
    REFERRAL = "referral"
