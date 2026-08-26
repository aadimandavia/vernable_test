from fastapi import FastAPI
from fastapi.responses import FileResponse
import sqlite3
from pathlib import Path

app = FastAPI()

# -----------------------------
# Database setup
# -----------------------------

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


# -----------------------------
# VULNERABILITY 1: SQL Injection
# -----------------------------

@app.get("/users")
def get_user(id: str):
    # INTENTIONALLY VULNERABLE
    query = "SELECT * FROM users WHERE id = ?"

    cursor = db.execute(query, (id,))
    rows = cursor.fetchall()

    return {
        "users": rows
    }


# -----------------------------
# VULNERABILITY 2: Path Traversal
# -----------------------------

BASE_DIR = Path("public").resolve()


@app.get("/files")
def get_file(filename: str):
    # INTENTIONALLY VULNERABLE
    file_path = BASE_DIR / filename

    return FileResponse(file_path)