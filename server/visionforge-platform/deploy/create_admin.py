"""Create admin account with a strong random password."""
import secrets
from app.database import get_connection
from app.security import hash_password

username = "superadmin"
password = secrets.token_urlsafe(16)
password_hash = hash_password(password)

conn = get_connection()
conn.execute(
    "INSERT OR REPLACE INTO users (username, email, password_hash, is_admin) VALUES (?, ?, ?, 1)",
    (username, "admin@vf.com", password_hash),
)
conn.commit()
conn.close()

print("Admin created!")
print(f"  Username: {username}")
print(f"  Password: {password}")
print("  Login at: http://81.70.189.154/login")
