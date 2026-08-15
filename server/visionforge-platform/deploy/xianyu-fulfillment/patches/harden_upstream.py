#!/usr/bin/env python3
"""Apply fail-closed security fixes to the pinned Xianyu upstream image."""
from __future__ import annotations

import argparse
from pathlib import Path


DB_PASSWORD_SENTINEL = "visionforge-admin-password-from-env"
LOG_PATH_SENTINEL = "visionforge-non-root-log-path"
CARD_UPDATE_LOG_SENTINEL = "visionforge-redacted-card-update-log"
SQL_PARAMETER_LOG_SENTINEL = "visionforge-redacted-sql-parameters"
SQL_PARAMETER_LOG_START = "        sql_lower = formatted_sql.lower()\n"
SQL_PARAMETER_LOG_BLOCK = (
    SQL_PARAMETER_LOG_START
    +
    "        sensitive_keywords = (\n"
    "            'password',\n"
    "            'proxy_pass',\n"
    "            'smtp_password',\n"
    "            'admin_password_hash',\n"
    "            'api_config',\n"
    "            'authorization',\n"
    "            'token',\n"
    "            'chat_messages',\n"
    "            'delivery_meta',\n"
    "        )\n"
    "        contains_sensitive = any(keyword in sql_lower for keyword in sensitive_keywords)\n"
    "\n"
    "        # 格式化参数\n"
    '        params_str = ""\n'
    "        if params:\n"
    "            # 包含敏感字段的SQL统一脱敏参数，避免日志泄露密码等敏感信息\n"
    "            if contains_sensitive:\n"
    "                if isinstance(params, (list, tuple)):\n"
    '                    params_str = f" | 参数: [***敏感参数已脱敏，共{len(params)}项***]"\n'
    "                else:\n"
    '                    params_str = " | 参数: [***敏感参数已脱敏***]"\n'
    "            elif isinstance(params, (list, tuple)):\n"
    "                if len(params) > 0:\n"
    "                    # 限制参数长度，避免日志过长\n"
    "                    formatted_params = []\n"
    "                    for param in params:\n"
    "                        if isinstance(param, str) and len(param) > 100:\n"
    '                            formatted_params.append(f"{param[:100]}...")\n'
    "                        else:\n"
    "                            formatted_params.append(repr(param))\n"
    "                    params_str = f\" | 参数: [{', '.join(formatted_params)}]\"\n"
    "            else:\n"
    '                params_str = f" | 参数: {repr(params)}"\n'
    "\n"
)
REDACTED_SQL_PARAMETER_LOG_BLOCK = (
    "        # visionforge-redacted-sql-parameters\n"
    '        params_str = ""\n'
    "        if params:\n"
    "            parameter_count = len(params) if isinstance(params, (list, tuple)) else 1\n"
    '            params_str = f" | 参数: [***参数值已脱敏，共{parameter_count}项***]"'
)
SAFE_CARD_UPDATE_LOG_BLOCK = (
    '                logger.info(\n'
    '                    f"[DEBUG DB] 更新卡券字段: card_id={card_id}, "\n'
    '                    f"field_count={len(update_fields) - 1}"\n'
    '                )'
)
FORBIDDEN_DATABASE_LOG_FRAGMENTS = (
    '[DEBUG DB] 参数: {params}',
    "formatted_params.append(repr(param))",
    "param[:100]",
    "参数: {repr(params)}",
)


def _replace_once(path: Path, old: str, new: str) -> None:
    content = path.read_text(encoding="utf-8")
    count = content.count(old)
    if count != 1:
        raise RuntimeError(f"expected one patch point in {path}, found {count}")
    path.write_text(content.replace(old, new, 1), encoding="utf-8")


def _verify_database_hardening(database_path: Path) -> None:
    content = database_path.read_text(encoding="utf-8")
    for sentinel in (DB_PASSWORD_SENTINEL, CARD_UPDATE_LOG_SENTINEL, SQL_PARAMETER_LOG_SENTINEL):
        if content.count(sentinel) != 1:
            raise RuntimeError(f"database hardening sentinel invalid: {sentinel}")
    for fragment in FORBIDDEN_DATABASE_LOG_FRAGMENTS:
        if fragment in content:
            raise RuntimeError(f"unsafe database logging remains: {fragment}")


def patch_tree(root: Path) -> None:
    database_path = root / "db_manager.py"
    database_content = database_path.read_text(encoding="utf-8")
    if DB_PASSWORD_SENTINEL not in database_content:
        _replace_once(
            database_path,
            '                default_password_hash = hashlib.sha256("admin123".encode()).hexdigest()',
            '                # visionforge-admin-password-from-env\n'
            '                configured_password = os.getenv("ADMIN_PASSWORD", "")\n'
            '                if len(configured_password) < 20 or configured_password == "admin123":\n'
            '                    raise RuntimeError("ADMIN_PASSWORD must be a non-default value of at least 20 characters")\n'
            '                default_password_hash = hashlib.sha256(configured_password.encode()).hexdigest()',
        )

    database_content = database_path.read_text(encoding="utf-8")
    if SQL_PARAMETER_LOG_SENTINEL not in database_content:
        _replace_once(database_path, SQL_PARAMETER_LOG_BLOCK, REDACTED_SQL_PARAMETER_LOG_BLOCK)

    database_content = database_path.read_text(encoding="utf-8")
    if CARD_UPDATE_LOG_SENTINEL not in database_content:
        legacy_block = (
            '                logger.info(f"[DEBUG DB] 执行SQL: {sql}")\n'
            '                logger.info(f"[DEBUG DB] 参数: {params}")'
        )
        if legacy_block in database_content:
            replacement = (
                '                # visionforge-redacted-card-update-log\n'
                '                logger.info(\n'
                '                    f"[DEBUG DB] 卡券更新语句已准备，字段数: {len(update_fields)}"\n'
                '                )'
            )
            _replace_once(database_path, legacy_block, replacement)
        elif SAFE_CARD_UPDATE_LOG_BLOCK in database_content:
            _replace_once(
                database_path,
                SAFE_CARD_UPDATE_LOG_BLOCK,
                '                # visionforge-redacted-card-update-log\n'
                + SAFE_CARD_UPDATE_LOG_BLOCK,
            )
        else:
            raise RuntimeError(f"card update log patch point missing in {database_path}")

    _verify_database_hardening(database_path)

    server_path = root / "reply_server.py"
    server_content = server_path.read_text(encoding="utf-8")
    if 'DEFAULT_ADMIN_PASSWORD = ""' not in server_content:
        _replace_once(
            server_path,
            'DEFAULT_ADMIN_PASSWORD = "admin123"  # 系统初始化时的默认密码',
            'DEFAULT_ADMIN_PASSWORD = ""  # 默认密码已禁用；首次密码仅从部署环境注入',
        )

    login_path = root / "static" / "login.html"
    login_content = login_path.read_text(encoding="utf-8")
    if "由部署管理员保管" not in login_content:
        _replace_once(
            login_path,
            '<code class="bg-white px-2 py-1 rounded">admin123</code>',
            '<span class="text-muted">由部署管理员保管</span>',
        )
        _replace_once(
            login_path,
            "document.getElementById('password').value = 'admin123';",
            "document.getElementById('password').value = '';",
        )

    log_collector_path = root / "file_log_collector.py"
    log_collector_content = log_collector_path.read_text(encoding="utf-8")
    if LOG_PATH_SENTINEL not in log_collector_content:
        _replace_once(
            log_collector_path,
            '            self.log_file = "realtime.log"',
            '            # visionforge-non-root-log-path\n'
            '            self.log_file = os.getenv("REALTIME_LOG_PATH", "logs/realtime.log")',
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path("/app"))
    args = parser.parse_args()
    patch_tree(args.root.resolve())


if __name__ == "__main__":
    main()
