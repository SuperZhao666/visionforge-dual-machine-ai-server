import os
import secrets
import sys

import paramiko

HOST = os.getenv("VISIONFORGE_SSH_HOST", "81.70.189.154")
USER = os.getenv("VISIONFORGE_SSH_USER", "ubuntu")
PASS = os.getenv("VISIONFORGE_SSH_PASSWORD", "")
if not PASS:
    print("Set VISIONFORGE_SSH_PASSWORD before running deploy/fix_admin.py", file=sys.stderr)
    raise SystemExit(2)

def ssh(cmd, timeout=60):
    c = paramiko.SSHClient()
    c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    c.connect(HOST, username=USER, password=PASS, timeout=20)
    stdin, stdout, stderr = c.exec_command(cmd, timeout=timeout)
    out = stdout.read().decode().strip()
    err = stderr.read().decode().strip()
    c.close()
    return out, err

# Init DB
print("=== Init DB ===")
out, err = ssh(
    "cd /home/ubuntu/vf-platform && "
    "venv/bin/python3 -c 'from app.database import init_db; init_db(); print(\"DB_OK\")'"
)
print(out)
if err:
    print("ERR:", err[:200])

# Create admin
admin_pw = secrets.token_urlsafe(16)
print("=== Create admin ===")
out, err = ssh(
    "cd /home/ubuntu/vf-platform && "
    f"venv/bin/python3 -c \""
    f"from app.database import get_connection; "
    f"from app.security import hash_password; "
    f"conn = get_connection(); "
    f"conn.execute('INSERT OR REPLACE INTO users (username, email, password_hash, is_admin) VALUES (?, ?, ?, 1)', "
    f"('superadmin', 'a@vf.com', hash_password('{admin_pw}'))); "
    f"conn.commit(); conn.close(); "
    f"print('ADMIN_CREATED')\""
)
print(out)
if err:
    print("ERR:", err[:300])

# Verify
out, err = ssh("curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8000/login")
print(f"Site: HTTP {out}")

print()
print("LOGIN: http://81.70.189.154/login")
print("User: superadmin")
print(f"Pass: {admin_pw}")
