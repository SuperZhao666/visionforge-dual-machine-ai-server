"""Application configuration loaded from .env file."""
import os
import secrets
from pathlib import Path
from urllib.parse import urlsplit

from dotenv import load_dotenv

# Load .env from project root
_env_path = Path(__file__).resolve().parents[2] / ".env"
if _env_path.exists():
    load_dotenv(_env_path)
else:
    load_dotenv()


_SITE_URL = os.getenv("SITE_URL", "http://localhost:8000").strip()
_ENVIRONMENT = os.getenv("ENVIRONMENT", "").strip().lower()
if not _ENVIRONMENT:
    _ENVIRONMENT = "production" if _SITE_URL.lower().startswith("https://") else "development"


def _is_https_origin(value: str) -> bool:
    try:
        parsed = urlsplit(str(value or "").strip())
    except ValueError:
        return False
    return bool(
        parsed.scheme.lower() == "https"
        and parsed.hostname
        and parsed.username is None
        and parsed.password is None
        and parsed.path in {"", "/"}
        and not parsed.query
        and not parsed.fragment
    )


class Config:
    # Security — MUST be set in production
    SECRET_KEY: str = os.getenv("SECRET_KEY", "")
    ENVIRONMENT: str = _ENVIRONMENT
    # Public API documentation is useful for local development/tests only.
    # Production defaults to disabled and rejects an explicit override.
    PUBLIC_API_DOCS_ENABLED: bool = os.getenv(
        "PUBLIC_API_DOCS_ENABLED",
        "0" if ENVIRONMENT == "production" else "1",
    ).strip().lower() in {"1", "true", "yes"}

    # Database
    DATABASE_PATH: str = os.getenv(
        "DATABASE_PATH",
        str(Path(__file__).resolve().parents[2] / "data" / "vf.db"),
    )

    # Loopback-only bridge into the separately isolated dual-machine sidecar.
    DUAL_MACHINE_ADMIN_BASE_URL: str = os.getenv(
        "DUAL_MACHINE_ADMIN_BASE_URL",
        "http://127.0.0.1:8010",
    ).rstrip("/")
    DUAL_MACHINE_ADMIN_BRIDGE_SECRET: str = os.getenv(
        "DUAL_MACHINE_ADMIN_BRIDGE_SECRET",
        "",
    )

    # V免签 (vmq-itchat) webhook
    VMQ_WEBHOOK_SECRET: str = os.getenv("VMQ_WEBHOOK_SECRET", "")
    VMQ_MONITOR_HOST: str = os.getenv("VMQ_MONITOR_HOST", "")

    # On-demand redemption and private code issuance. Keep these in deployment env only.
    REDEMPTION_CODE_SECRET: str = os.getenv("REDEMPTION_CODE_SECRET", "")
    CODE_ISSUANCE_SERVICE_ID: str = os.getenv(
        "CODE_ISSUANCE_SERVICE_ID",
        os.getenv("FULFILLMENT_SERVICE_ID", "xianyu-code-bridge"),
    )
    CODE_ISSUANCE_HMAC_SECRET: str = os.getenv(
        "CODE_ISSUANCE_HMAC_SECRET",
        os.getenv("FULFILLMENT_HMAC_SECRET", ""),
    )
    CODE_ISSUANCE_MAX_SKEW_SECONDS: int = int(
        os.getenv("CODE_ISSUANCE_MAX_SKEW_SECONDS", os.getenv("FULFILLMENT_MAX_SKEW_SECONDS", "300"))
    )

    # RSA license keys
    PRIVATE_KEY_PATH: str = os.getenv(
        "PRIVATE_KEY_PATH",
        str(Path(__file__).resolve().parents[2] / "owner_keys" / "license_private_key.pem"),
    )
    PRIVATE_KEY_PASSWORD: str = os.getenv("PRIVATE_KEY_PASSWORD", "")
    ALLOW_INSECURE_RUNTIME_LEASE_HMAC: bool = os.getenv(
        "ALLOW_INSECURE_RUNTIME_LEASE_HMAC",
        "0",
    ).strip().lower() in {"1", "true", "yes"}
    REQUIRE_RUNTIME_INSTANCE_ID: bool = os.getenv(
        "REQUIRE_RUNTIME_INSTANCE_ID",
        "1",
    ).strip().lower() in {"1", "true", "yes"}
    # HTTPS production deployments must not silently inherit a legacy
    # runtime_security_settings row with integrity enforcement disabled.
    REQUIRE_RUNTIME_INTEGRITY: bool = os.getenv(
        "REQUIRE_RUNTIME_INTEGRITY",
        (
            "1"
            if ENVIRONMENT == "production" or _SITE_URL.lower().startswith("https://")
            else "0"
        ),
    ).strip().lower() in {"1", "true", "yes"}

    # Log storage
    LOG_STORAGE_PATH: str = os.getenv(
        "LOG_STORAGE_PATH",
        str(Path(__file__).resolve().parents[2] / "log_storage"),
    )

    # Site metadata
    SITE_NAME: str = os.getenv("SITE_NAME", "VisionForge")
    SITE_URL: str = _SITE_URL
    DOWNLOAD_URL: str = os.getenv("DOWNLOAD_URL", SITE_URL.rstrip("/") + "/static/releases/")
    DOWNLOAD_TEXT: str = os.getenv("DOWNLOAD_TEXT", "下载最新版本")
    # Application-private runtime delivery.  The Ed25519 private key is kept
    # offline and is intentionally not represented in server configuration.
    RUNTIME_CATALOG_PUBLIC_KEY: str = os.getenv("RUNTIME_CATALOG_PUBLIC_KEY", "")
    RUNTIME_CATALOG_PUBLIC_KEY_PATH: str = os.getenv("RUNTIME_CATALOG_PUBLIC_KEY_PATH", "")
    RUNTIME_ARTIFACT_ROOT: str = os.getenv(
        "RUNTIME_ARTIFACT_ROOT",
        str(Path(__file__).resolve().parents[1] / "runtime_artifacts"),
    )
    RUNTIME_ARTIFACT_HMAC_SECRET: str = os.getenv("RUNTIME_ARTIFACT_HMAC_SECRET", "")
    RUNTIME_ARTIFACT_TTL_SECONDS: int = int(
        os.getenv("RUNTIME_ARTIFACT_TTL_SECONDS", "900") or "900"
    )
    IP_GEOLOOKUP_URL_TEMPLATE: str = os.getenv(
        "IP_GEOLOOKUP_URL_TEMPLATE",
        "http://ip-api.com/json/{ip}?lang=zh-CN&fields=status,country,regionName,city,isp,lat,lon,query",
    )
    IP_GEOLOOKUP_TIMEOUT_SECONDS: float = float(os.getenv("IP_GEOLOOKUP_TIMEOUT_SECONDS", "1.5") or "1.5")

    # Outbound verification email. Credentials must be supplied by the deploy environment.
    SMTP_HOST: str = os.getenv("SMTP_HOST", "smtp.qq.com")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", "587") or "587")
    SMTP_USER: str = os.getenv("SMTP_USER", "")
    SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "")
    SMTP_USE_TLS: bool = os.getenv("SMTP_USE_TLS", "1").strip().lower() not in {"0", "false", "no"}
    EMAIL_CODE_SEND_COOLDOWN_SECONDS: int = int(os.getenv("EMAIL_CODE_SEND_COOLDOWN_SECONDS", "60") or "60")

    # Admin TOTP (optional 2FA — set to enable)
    ADMIN_TOTP_SECRET: str = os.getenv("ADMIN_TOTP_SECRET", "")
    COOKIE_SECURE: bool = os.getenv(
        "COOKIE_SECURE",
        "1" if ENVIRONMENT == "production" or SITE_URL.lower().startswith("https://") else "0",
    ).strip().lower() not in {"0", "false", "no"}

    @classmethod
    def validate(cls) -> list[str]:
        errors: list[str] = []
        environment = str(cls.ENVIRONMENT or "").strip().lower()
        site_url = str(cls.SITE_URL or "").strip()
        if environment not in {"production", "development", "test"}:
            errors.append("ENVIRONMENT must be production, development, or test")
        if not cls.SECRET_KEY or len(cls.SECRET_KEY) < 32:
            errors.append("SECRET_KEY must be at least 32 characters")
        if cls.REDEMPTION_CODE_SECRET and len(cls.REDEMPTION_CODE_SECRET) < 32:
            errors.append("REDEMPTION_CODE_SECRET must be at least 32 characters when configured")
        if (
            cls.DUAL_MACHINE_ADMIN_BRIDGE_SECRET
            and len(cls.DUAL_MACHINE_ADMIN_BRIDGE_SECRET.encode("utf-8")) < 32
        ):
            errors.append(
                "DUAL_MACHINE_ADMIN_BRIDGE_SECRET must contain at least 32 bytes when configured"
            )
        if cls.DUAL_MACHINE_ADMIN_BASE_URL not in {
            "http://127.0.0.1:8010",
            "http://localhost:8010",
            "http://[::1]:8010",
        }:
            errors.append("DUAL_MACHINE_ADMIN_BASE_URL must remain loopback-only on port 8010")
        if cls.CODE_ISSUANCE_HMAC_SECRET and len(cls.CODE_ISSUANCE_HMAC_SECRET) < 32:
            errors.append("CODE_ISSUANCE_HMAC_SECRET must be at least 32 characters when configured")
        if not 30 <= int(cls.CODE_ISSUANCE_MAX_SKEW_SECONDS) <= 900:
            errors.append("CODE_ISSUANCE_MAX_SKEW_SECONDS must be between 30 and 900")
        if cls.RUNTIME_ARTIFACT_HMAC_SECRET and len(cls.RUNTIME_ARTIFACT_HMAC_SECRET) < 32:
            errors.append("RUNTIME_ARTIFACT_HMAC_SECRET must be at least 32 characters when configured")
        if cls.RUNTIME_ARTIFACT_HMAC_SECRET.lower().startswith("change-me"):
            errors.append("RUNTIME_ARTIFACT_HMAC_SECRET must not use the example placeholder")
        if not 60 <= int(cls.RUNTIME_ARTIFACT_TTL_SECONDS) <= 3600:
            errors.append("RUNTIME_ARTIFACT_TTL_SECONDS must be between 60 and 3600")
        if site_url.lower().startswith("https://") and not cls.REQUIRE_RUNTIME_INTEGRITY:
            errors.append(
                "REQUIRE_RUNTIME_INTEGRITY must remain enabled for HTTPS production"
            )
        if site_url.lower().startswith("https://") and not cls.COOKIE_SECURE:
            errors.append("HTTPS SITE_URL requires COOKIE_SECURE=1")
        if environment == "production":
            if not _is_https_origin(site_url):
                errors.append("production SITE_URL must be an origin-only HTTPS URL")
            if not cls.REQUIRE_RUNTIME_INTEGRITY:
                errors.append("production requires REQUIRE_RUNTIME_INTEGRITY=1")
            if not cls.REQUIRE_RUNTIME_INSTANCE_ID:
                errors.append("production requires REQUIRE_RUNTIME_INSTANCE_ID=1")
            if cls.ALLOW_INSECURE_RUNTIME_LEASE_HMAC:
                errors.append("production forbids ALLOW_INSECURE_RUNTIME_LEASE_HMAC")
            if not cls.COOKIE_SECURE:
                errors.append("production requires COOKIE_SECURE=1")
            if cls.PUBLIC_API_DOCS_ENABLED:
                errors.append("production forbids PUBLIC_API_DOCS_ENABLED")
        if not 10 <= int(cls.EMAIL_CODE_SEND_COOLDOWN_SECONDS) <= 3600:
            errors.append("EMAIL_CODE_SEND_COOLDOWN_SECONDS must be between 10 and 3600")
        return errors


config = Config()

# Enforce SECRET_KEY at import time — refuse to start without it
_validation_errors = config.validate()
if _validation_errors:
    raise RuntimeError(
        "Configuration error(s):\n  " + "\n  ".join(_validation_errors) +
        "\n\nSet SECRET_KEY in your .env file. Example:\n"
        "  SECRET_KEY=" + secrets.token_hex(32)
    )
