from app.database import get_connection, init_db

conn = get_connection()
conn.execute("ALTER TABLE license_keys RENAME TO license_keys_old")
conn.commit()
init_db()
print("SCHEMA FIXED")
