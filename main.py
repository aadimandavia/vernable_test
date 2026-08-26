from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pathlib import Path
import sqlite3
import os

app = FastAPI()

# ============================================================
# DATABASE SETUP
# ============================================================

db = sqlite3.connect("users.db", check_same_thread=False)

db.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    name TEXT
)
""")

db.execute("INSERT OR IGNORE INTO users VALUES (1, 'Alice')")
db.execute("INSERT OR IGNORE INTO users VALUES (2, 'Bob')")
db.commit()


# ============================================================
# VULNERABILITY 1 — SQL INJECTION (CWE-89)
# ============================================================

@app.get("/users")
def get_user(id: str):
    # INTENTIONALLY VULNERABLE
    #
    # User-controlled "id" flows directly into SQL.
    query = "SELECT * FROM users WHERE id = " + id

    cursor = db.execute(query)
    rows = cursor.fetchall()

    return {
        "users": rows
    }


# ============================================================
# VULNERABILITY 2 — PATH TRAVERSAL (CWE-22)
# ============================================================

BASE_DIR = Path("files").resolve()

# Create a harmless test directory.
BASE_DIR.mkdir(exist_ok=True)

(BASE_DIR / "public.txt").write_text(
    "This is a public file."
)

# Create a harmless file outside the allowed directory.
SECRET_DIR = Path("sandbox_secret").resolve()
SECRET_DIR.mkdir(exist_ok=True)

(SECRET_DIR / "secret.txt").write_text(
    "This is a synthetic secret file."
)


@app.get("/download")
def download_file(filename: str):
    # INTENTIONALLY VULNERABLE
    #
    # User-controlled filename is directly appended to BASE_DIR.
    #
    # Example malicious input:
    #
    # ../sandbox_secret/secret.txt
    #
    # can escape BASE_DIR.

    file_path = BASE_DIR / filename

    return FileResponse(file_path)
