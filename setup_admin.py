import os
import sqlite3
import getpass
from pathlib import Path
from werkzeug.security import generate_password_hash

DB = Path(__file__).resolve().parent / "database" / "ajwears.db"

email = input("Admin email: ").strip().lower()
password = getpass.getpass("Admin password (8+ chars): ")

if len(password) < 8:
    raise SystemExit("Password must be at least 8 characters.")

name = input("Admin name [AJWEARS Admin]: ").strip() or "AJWEARS Admin"

password_hash = generate_password_hash(password)

c = sqlite3.connect(DB)
c.execute("PRAGMA foreign_keys=ON")

c.execute(
    """
    INSERT INTO users (name, email, password_hash, role)
    VALUES (?, ?, ?, ?)
    ON CONFLICT(email) DO UPDATE SET
        name = excluded.name,
        password_hash = excluded.password_hash,
        role = 'super_admin',
        active = 1
    """,
    (name, email, password_hash, "super_admin")
)

c.commit()
c.close()

print("Super admin ready. Open /admin and sign in.")