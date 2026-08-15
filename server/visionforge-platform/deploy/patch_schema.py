from app.database import get_connection, init_db

init_db()
conn = get_connection()

# Add missing columns (ignore errors if already exist)
for col, table in [
    ('ip_address TEXT DEFAULT ""', 'orders'),
    ('expires_at TEXT', 'license_keys_old'),
]:
    try:
        conn.execute(f'ALTER TABLE {table} ADD COLUMN {col}')
        conn.commit()
        print(f'Added {col} to {table}')
    except Exception as e:
        print(f'{table}.{col}: {e}')

# Also add login_attempts table if missing
try:
    conn.execute('''CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        ip TEXT NOT NULL,
        success INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT (datetime("now"))
    )''')
    conn.commit()
    print('login_attempts table ready')
except Exception as e:
    print(f'login_attempts: {e}')

# Add email_codes table
try:
    conn.execute('''CREATE TABLE IF NOT EXISTS email_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT NOT NULL, code TEXT NOT NULL,
        purpose TEXT NOT NULL DEFAULT "reset_password",
        used INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL DEFAULT (datetime("now"))
    )''')
    conn.commit()
    print('email_codes table ready')
except Exception as e:
    print(f'email_codes: {e}')

conn.close()
print('SCHEMA PATCH DONE')
