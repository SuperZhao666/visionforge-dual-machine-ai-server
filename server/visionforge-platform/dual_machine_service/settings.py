"""Environment-owned settings for the isolated dual-machine sidecar."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path

from .versions import normalize_client_version

_PLACEHOLDER_PREFIXES = ("change-me", "replace-with", "example")
_DEFAULT_DATABASE_PATH = (
    Path(__file__).resolve().parents[1]
    / "data"
    / "vf_dual_machine.db"
)
_MAX_PAIR_CREDENTIAL_PREVIOUS_PUBLIC_KEYS = 2
_MAX_PAIR_CREDENTIAL_ARCHIVED_PUBLIC_KEYS = 13
_MAX_PAIR_CREDENTIAL_VERIFICATION_KEYS = 16


@dataclass(frozen=True, slots=True)
class DualMachineSettings:
    database_path: Path
    license_code_secret: bytes = field(repr=False)
    token_secret: bytes = field(repr=False)
    minimum_host_client_version: str
    minimum_android_client_version: str
    license_code_key_version: int = 1
    license_code_previous_keys: tuple[tuple[int, bytes], ...] = field(
        default=(),
        repr=False,
    )
    ticket_private_key_path: Path | None = None
    ticket_public_key_path: Path | None = None
    ticket_previous_public_key_paths: tuple[Path, ...] = ()
    ticket_private_key_password: str | None = field(
        default=None,
        repr=False,
    )
    pair_credential_private_key_path: Path | None = None
    pair_credential_public_key_path: Path | None = None
    pair_credential_previous_public_key_paths: tuple[Path, ...] = ()
    pair_credential_archived_public_key_paths: tuple[Path, ...] = ()
    pair_credential_private_key_password: str | None = field(
        default=None,
        repr=False,
    )
    pair_credential_ttl_seconds: int = 15
    bind_host: str = "127.0.0.1"
    bind_port: int = 8010
    usage_lease_ttl_seconds: int = 5
    # A successor still starts exactly at the current lease expiry.  Issuing
    # it earlier only gives WAN/TLS/signing latency enough time to deliver the
    # contiguous permit before the five-second data-plane segment closes.
    usage_renewal_window_seconds: int = 4
    admin_bridge_secret: bytes = field(default=b"", repr=False)
    admin_bridge_max_skew_seconds: int = 30

    @classmethod
    def from_environment(cls) -> "DualMachineSettings":
        private_path = str(
            os.getenv("DUAL_MACHINE_TICKET_PRIVATE_KEY_PATH", "")
        ).strip()
        public_path = str(
            os.getenv("DUAL_MACHINE_TICKET_PUBLIC_KEY_PATH", "")
        ).strip()
        password = os.getenv("DUAL_MACHINE_TICKET_PRIVATE_KEY_PASSWORD")
        pair_private_path = str(
            os.getenv("DUAL_MACHINE_PAIR_CREDENTIAL_PRIVATE_KEY_PATH", "")
        ).strip()
        pair_public_path = str(
            os.getenv("DUAL_MACHINE_PAIR_CREDENTIAL_PUBLIC_KEY_PATH", "")
        ).strip()
        pair_password = os.getenv(
            "DUAL_MACHINE_PAIR_CREDENTIAL_PRIVATE_KEY_PASSWORD",
        )
        return cls(
            database_path=Path(
                os.getenv(
                    "DUAL_MACHINE_DATABASE_PATH",
                    str(_DEFAULT_DATABASE_PATH),
                )
            ),
            license_code_secret=os.getenv(
                "DUAL_MACHINE_LICENSE_CODE_SECRET",
                "",
            ).encode("utf-8"),
            token_secret=os.getenv(
                "DUAL_MACHINE_TOKEN_SECRET",
                "",
            ).encode("utf-8"),
            minimum_host_client_version=str(
                os.getenv("DUAL_MACHINE_MIN_HOST_CLIENT_VERSION", ""),
            ).strip(),
            minimum_android_client_version=str(
                os.getenv("DUAL_MACHINE_MIN_ANDROID_CLIENT_VERSION", ""),
            ).strip(),
            license_code_key_version=int(
                os.getenv("DUAL_MACHINE_LICENSE_CODE_KEY_VERSION", "1"),
            ),
            license_code_previous_keys=_parse_previous_license_keys(
                os.getenv(
                    "DUAL_MACHINE_LICENSE_CODE_PREVIOUS_KEYS_JSON",
                    "",
                ),
            ),
            ticket_private_key_path=Path(private_path) if private_path else None,
            ticket_public_key_path=Path(public_path) if public_path else None,
            ticket_previous_public_key_paths=(
                _parse_previous_ticket_public_key_paths(
                    os.getenv(
                        "DUAL_MACHINE_TICKET_PREVIOUS_PUBLIC_KEYS_JSON",
                        "",
                    ),
                )
            ),
            ticket_private_key_password=password or None,
            pair_credential_private_key_path=(
                Path(pair_private_path) if pair_private_path else None
            ),
            pair_credential_public_key_path=(
                Path(pair_public_path) if pair_public_path else None
            ),
            pair_credential_previous_public_key_paths=(
                _parse_public_key_paths(
                    os.getenv(
                        "DUAL_MACHINE_PAIR_CREDENTIAL_PREVIOUS_PUBLIC_KEYS_JSON",
                        "",
                    ),
                    setting_name=(
                        "DUAL_MACHINE_PAIR_CREDENTIAL_PREVIOUS_PUBLIC_KEYS_JSON"
                    ),
                    maximum_paths=(
                        _MAX_PAIR_CREDENTIAL_PREVIOUS_PUBLIC_KEYS
                    ),
                )
            ),
            pair_credential_archived_public_key_paths=(
                _parse_public_key_paths(
                    os.getenv(
                        "DUAL_MACHINE_PAIR_CREDENTIAL_ARCHIVED_PUBLIC_KEYS_JSON",
                        "",
                    ),
                    setting_name=(
                        "DUAL_MACHINE_PAIR_CREDENTIAL_ARCHIVED_PUBLIC_KEYS_JSON"
                    ),
                    maximum_paths=(
                        _MAX_PAIR_CREDENTIAL_ARCHIVED_PUBLIC_KEYS
                    ),
                )
            ),
            pair_credential_private_key_password=pair_password or None,
            pair_credential_ttl_seconds=int(
                os.getenv(
                    "DUAL_MACHINE_PAIR_CREDENTIAL_TTL_SECONDS",
                    "15",
                ),
            ),
            bind_host=str(
                os.getenv("DUAL_MACHINE_BIND_HOST", "127.0.0.1")
            ).strip(),
            bind_port=int(os.getenv("DUAL_MACHINE_BIND_PORT", "8010")),
            usage_lease_ttl_seconds=int(
                os.getenv("DUAL_MACHINE_USAGE_LEASE_TTL_SECONDS", "5"),
            ),
            usage_renewal_window_seconds=int(
                os.getenv(
                    "DUAL_MACHINE_USAGE_RENEWAL_WINDOW_SECONDS",
                    "4",
                ),
            ),
            admin_bridge_secret=os.getenv(
                "DUAL_MACHINE_ADMIN_BRIDGE_SECRET",
                "",
            ).encode("utf-8"),
            admin_bridge_max_skew_seconds=int(
                os.getenv(
                    "DUAL_MACHINE_ADMIN_BRIDGE_MAX_SKEW_SECONDS",
                    "30",
                ),
            ),
        )

    def validate_runtime(self) -> None:
        errors = self.validation_errors(
            require_ticket_keys=True,
            require_pair_credential_keys=True,
        )
        if errors:
            raise ValueError("; ".join(errors))

    def validate_usage(self) -> None:
        errors = self.validation_errors(require_ticket_keys=True)
        if errors:
            raise ValueError("; ".join(errors))

    def validate_activation(self) -> None:
        errors = self.validation_errors(require_ticket_keys=False)
        if errors:
            raise ValueError("; ".join(errors))

    def validate_card_issuance(self) -> None:
        errors = self.validation_errors(require_ticket_keys=False)
        errors = [
            error
            for error in errors
            if "DUAL_MACHINE_TOKEN_SECRET" not in error
        ]
        if errors:
            raise ValueError("; ".join(errors))

    def validation_errors(
        self,
        *,
        require_ticket_keys: bool,
        require_pair_credential_keys: bool = False,
    ) -> list[str]:
        errors: list[str] = []
        _validate_secret(
            self.license_code_secret,
            "DUAL_MACHINE_LICENSE_CODE_SECRET",
            errors,
        )
        _validate_secret(
            self.token_secret,
            "DUAL_MACHINE_TOKEN_SECRET",
            errors,
        )
        if not 1 <= int(self.license_code_key_version) <= 2_147_483_647:
            errors.append(
                "DUAL_MACHINE_LICENSE_CODE_KEY_VERSION is invalid",
            )
        seen_versions = {int(self.license_code_key_version)}
        for version, secret in self.license_code_previous_keys:
            normalized_version = int(version)
            if normalized_version in seen_versions or normalized_version <= 0:
                errors.append(
                    "DUAL_MACHINE_LICENSE_CODE_PREVIOUS_KEYS_JSON "
                    "contains a duplicate or invalid version",
                )
                continue
            seen_versions.add(normalized_version)
            _validate_secret(
                secret,
                "DUAL_MACHINE_LICENSE_CODE_PREVIOUS_KEYS_JSON",
                errors,
            )
        _validate_client_version_setting(
            self.minimum_host_client_version,
            "DUAL_MACHINE_MIN_HOST_CLIENT_VERSION",
            errors,
        )
        _validate_client_version_setting(
            self.minimum_android_client_version,
            "DUAL_MACHINE_MIN_ANDROID_CLIENT_VERSION",
            errors,
        )
        if not str(self.database_path):
            errors.append("DUAL_MACHINE_DATABASE_PATH is required")
        if self.database_path.name.casefold() == "vf.db":
            errors.append(
                "DUAL_MACHINE_DATABASE_PATH must not use the single-machine database",
            )
        if self.bind_host not in {"127.0.0.1", "::1", "localhost"}:
            errors.append(
                "DUAL_MACHINE_BIND_HOST must remain loopback-only",
            )
        if not 1 <= int(self.bind_port) <= 65535:
            errors.append("DUAL_MACHINE_BIND_PORT is invalid")
        if not 3 <= int(self.usage_lease_ttl_seconds) <= 10:
            errors.append(
                "DUAL_MACHINE_USAGE_LEASE_TTL_SECONDS must be between 3 and 10",
            )
        if not (
            1
            <= int(self.usage_renewal_window_seconds)
            < int(self.usage_lease_ttl_seconds)
        ):
            errors.append(
                "DUAL_MACHINE_USAGE_RENEWAL_WINDOW_SECONDS must be positive "
                "and shorter than the lease TTL",
            )
        if self.admin_bridge_secret:
            _validate_secret(
                self.admin_bridge_secret,
                "DUAL_MACHINE_ADMIN_BRIDGE_SECRET",
                errors,
            )
        if not 5 <= int(self.admin_bridge_max_skew_seconds) <= 300:
            errors.append(
                "DUAL_MACHINE_ADMIN_BRIDGE_MAX_SKEW_SECONDS must be between 5 and 300",
            )
        if require_ticket_keys:
            if self.ticket_private_key_path is None:
                errors.append(
                    "DUAL_MACHINE_TICKET_PRIVATE_KEY_PATH is required",
                )
            if self.ticket_public_key_path is None:
                errors.append(
                    "DUAL_MACHINE_TICKET_PUBLIC_KEY_PATH is required",
                )
            _validate_previous_ticket_key_paths(
                self.ticket_public_key_path,
                self.ticket_previous_public_key_paths,
                errors,
            )
        if require_pair_credential_keys:
            _validate_pair_credential_paths(self, errors)
        if not 1 <= int(self.pair_credential_ttl_seconds) <= 30:
            errors.append(
                "DUAL_MACHINE_PAIR_CREDENTIAL_TTL_SECONDS "
                "must be between 1 and 30",
            )
        return errors

    def license_code_keyring(self) -> dict[int, bytes]:
        keyring = {
            int(self.license_code_key_version): self.license_code_secret,
        }
        for version, secret in self.license_code_previous_keys:
            normalized_version = int(version)
            if normalized_version in keyring:
                raise ValueError("duplicate dual-machine license key version")
            keyring[normalized_version] = secret
        return keyring


def _validate_secret(
    secret: bytes,
    setting_name: str,
    errors: list[str],
) -> None:
    if len(secret) < 32:
        errors.append(f"{setting_name} must contain at least 32 bytes")
        return
    lowered = secret.decode("utf-8", "ignore").strip().lower()
    if lowered.startswith(_PLACEHOLDER_PREFIXES):
        errors.append(f"{setting_name} must not use a placeholder")


def _parse_previous_license_keys(
    raw_value: str,
) -> tuple[tuple[int, bytes], ...]:
    text = str(raw_value or "").strip()
    if not text:
        return ()
    try:
        payload = json.loads(text)
    except Exception as exc:
        raise ValueError(
            "DUAL_MACHINE_LICENSE_CODE_PREVIOUS_KEYS_JSON is invalid",
        ) from exc
    if not isinstance(payload, dict):
        raise ValueError(
            "DUAL_MACHINE_LICENSE_CODE_PREVIOUS_KEYS_JSON must be an object",
        )
    keys: list[tuple[int, bytes]] = []
    for raw_version, raw_secret in payload.items():
        try:
            version = int(raw_version)
        except Exception as exc:
            raise ValueError(
                "dual-machine previous license key version is invalid",
            ) from exc
        if not isinstance(raw_secret, str):
            raise ValueError(
                "dual-machine previous license key must be text",
            )
        keys.append((version, raw_secret.encode("utf-8")))
    return tuple(sorted(keys))


def _parse_previous_ticket_public_key_paths(
    raw_value: str,
) -> tuple[Path, ...]:
    return _parse_public_key_paths(
        raw_value,
        setting_name="DUAL_MACHINE_TICKET_PREVIOUS_PUBLIC_KEYS_JSON",
        maximum_paths=3,
    )


def _parse_public_key_paths(
    raw_value: str,
    *,
    setting_name: str,
    maximum_paths: int,
) -> tuple[Path, ...]:
    text = str(raw_value or "").strip()
    if not text:
        return ()
    try:
        payload = json.loads(text)
    except Exception as exc:
        raise ValueError(
            f"{setting_name} is invalid",
        ) from exc
    if not isinstance(payload, list) or not all(
        isinstance(value, str) and value.strip()
        for value in payload
    ):
        raise ValueError(
            f"{setting_name} must be an array of paths",
        )
    if len(payload) > maximum_paths:
        raise ValueError(
            f"{setting_name} must contain at most {maximum_paths} paths",
        )
    return tuple(Path(value.strip()) for value in payload)


def _validate_previous_ticket_key_paths(
    current_path: Path | None,
    previous_paths: tuple[Path, ...],
    errors: list[str],
) -> None:
    if len(previous_paths) > 3:
        errors.append(
            "DUAL_MACHINE_TICKET_PREVIOUS_PUBLIC_KEYS_JSON "
            "must contain at most 3 paths",
        )
        return
    seen: set[str] = set()
    if current_path is not None:
        seen.add(str(current_path.resolve()).casefold())
    for path in previous_paths:
        normalized = str(path.resolve()).casefold()
        if normalized in seen:
            errors.append(
                "DUAL_MACHINE_TICKET_PREVIOUS_PUBLIC_KEYS_JSON "
                "contains a duplicate path",
            )
            continue
        seen.add(normalized)


def _validate_pair_credential_paths(
    settings: DualMachineSettings,
    errors: list[str],
) -> None:
    if settings.pair_credential_private_key_path is None:
        errors.append(
            "DUAL_MACHINE_PAIR_CREDENTIAL_PRIVATE_KEY_PATH is required",
        )
    if settings.pair_credential_public_key_path is None:
        errors.append(
            "DUAL_MACHINE_PAIR_CREDENTIAL_PUBLIC_KEY_PATH is required",
        )
    if (
        len(settings.pair_credential_previous_public_key_paths)
        > _MAX_PAIR_CREDENTIAL_PREVIOUS_PUBLIC_KEYS
    ):
        errors.append(
            "DUAL_MACHINE_PAIR_CREDENTIAL_PREVIOUS_PUBLIC_KEYS_JSON "
            "must contain at most 2 paths",
        )
    if (
        len(settings.pair_credential_archived_public_key_paths)
        > _MAX_PAIR_CREDENTIAL_ARCHIVED_PUBLIC_KEYS
    ):
        errors.append(
            "DUAL_MACHINE_PAIR_CREDENTIAL_ARCHIVED_PUBLIC_KEYS_JSON "
            "must contain at most 13 paths",
        )
    verification_key_count = (
        (1 if settings.pair_credential_public_key_path is not None else 0)
        + len(settings.pair_credential_previous_public_key_paths)
        + len(settings.pair_credential_archived_public_key_paths)
    )
    if verification_key_count > _MAX_PAIR_CREDENTIAL_VERIFICATION_KEYS:
        errors.append(
            "pair credential verification keyring must contain at most "
            "16 public keys",
        )
    pair_paths = tuple(
        path
        for path in (
            settings.pair_credential_private_key_path,
            settings.pair_credential_public_key_path,
            *settings.pair_credential_previous_public_key_paths,
            *settings.pair_credential_archived_public_key_paths,
        )
        if path is not None
    )
    normalized_pair_paths = [
        str(path.resolve()).casefold() for path in pair_paths
    ]
    if len(set(normalized_pair_paths)) != len(normalized_pair_paths):
        errors.append(
            "dual-machine pair credential key paths contain duplicates",
        )
    ticket_paths = tuple(
        path
        for path in (
            settings.ticket_private_key_path,
            settings.ticket_public_key_path,
            *settings.ticket_previous_public_key_paths,
        )
        if path is not None
    )
    normalized_ticket_paths = {
        str(path.resolve()).casefold() for path in ticket_paths
    }
    if any(path in normalized_ticket_paths for path in normalized_pair_paths):
        errors.append(
            "pair credential and usage ticket key paths must be disjoint",
        )


def _validate_client_version_setting(
    value: str,
    setting_name: str,
    errors: list[str],
) -> None:
    try:
        normalize_client_version(value)
    except ValueError:
        errors.append(f"{setting_name} must be a numeric dotted version")
