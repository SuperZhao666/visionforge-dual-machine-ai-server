from __future__ import annotations
from pydantic import BaseModel, ConfigDict, Field
from typing import Optional


# --- Request models ---

class UserRegister(BaseModel):
    username: str = Field(..., min_length=2, max_length=32, pattern=r"^[a-zA-Z0-9_]+$")
    email: str = Field(default="", max_length=128)
    password: str = Field(..., min_length=6, max_length=128)


class UserLogin(BaseModel):
    username: str
    password: str


class OrderCreate(BaseModel):
    plan: str = Field(..., pattern=r"^(day|week|month|permanent)$")


class LicenseRequestModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LicenseActivateRequest(LicenseRequestModel):
    key_text: str = Field(..., min_length=10, max_length=2048)
    machine_code: str = Field(..., min_length=32, max_length=64)
    client_version: str = Field(default="", max_length=64)


class LicenseVerifyRequest(LicenseRequestModel):
    key_text: str = Field(..., min_length=10, max_length=2048)
    machine_code: str = Field(..., min_length=32, max_length=64)


class CrashReport(BaseModel):
    session_id: str = Field(..., max_length=64)
    machine_info: str = Field(default="{}")
    crash_type: str = Field(default="unhandled_exception")
    crash_data: str  # JSON string of crash context


# --- Response models ---

class UserResponse(BaseModel):
    id: int
    username: str
    email: str
    is_admin: bool
    created_at: str


class OrderResponse(BaseModel):
    id: int
    plan: str
    amount: float
    status: str
    created_at: str


class LicenseKeyResponse(BaseModel):
    id: int
    license_id: str
    plan: str
    features: str
    status: str
    hwid_hash: Optional[str] = None
    issued_at: str
    expires_at: str
    bound_at: Optional[str] = None


class LicenseActivateResponse(BaseModel):
    success: bool
    message: str
    plan: str = ""
    expires_at: str = ""
    features: str = ""


class LicenseVerifyResponse(BaseModel):
    valid: bool
    reason: str
    plan: str = ""
    days_left: Optional[int] = None


class ApiResponse(BaseModel):
    ok: bool
    message: str = ""
    data: Optional[dict] = None
