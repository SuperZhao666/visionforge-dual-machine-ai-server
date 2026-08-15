# Copy this file to config.py and fill in real values.
# config.py is gitignored — never commit secrets.

import os

os.environ.setdefault("SECRET_KEY", "change-me-to-random-64-chars")
os.environ.setdefault("DATABASE_PATH", "data/vf.db")
os.environ.setdefault("PAYJS_MCHID", "你的PayJS商户号")
os.environ.setdefault("PAYJS_KEY", "你的PayJS通信密钥")
os.environ.setdefault("PAYJS_NOTIFY_URL", "https://your-domain.com/api/payment/callback")
os.environ.setdefault("PRIVATE_KEY_PATH", "owner_keys/license_private_key.pem")
os.environ.setdefault("PRIVATE_KEY_PASSWORD", "strong-password-for-key-encryption")
os.environ.setdefault("LOG_STORAGE_PATH", "log_storage")
os.environ.setdefault("SITE_NAME", "VisionForge")
os.environ.setdefault("SITE_URL", "https://www.visionforge.cloud")
os.environ.setdefault("DOWNLOAD_URL", "https://www.visionforge.cloud/download")
os.environ.setdefault("DOWNLOAD_TEXT", "下载最新版本")
os.environ.setdefault("ADMIN_TOTP_SECRET", "")
# Runtime components use the same server and domain as the application.
os.environ.setdefault("RUNTIME_CATALOG_PUBLIC_KEY_PATH", "/etc/visionforge/runtime_catalog_public.pem")
os.environ.setdefault("RUNTIME_ARTIFACT_ROOT", "/home/ubuntu/vf-platform/runtime_artifacts")
os.environ.setdefault("RUNTIME_ARTIFACT_HMAC_SECRET", "change-me-to-at-least-32-random-characters")
os.environ.setdefault("RUNTIME_ARTIFACT_TTL_SECONDS", "900")
