from fastapi import FastAPI, Query
from fastapi.responses import FileResponse
import sqlite3
import os
from pathlib import Path

app = FastAPI(title="Cypher Multi-Variant Security Test")

DB_PATH = "users.db"
BASE_DIR = Path("files")


def get_db():
    return sqlite3.connect(DB_PATH)


# ============================================================
# SQL INJECTION VARIANT 1
# String concatenation
# ============================================================

@app.get("/users/concat")
def get_user_concat(id: str):
    db = get_db()

    query = "SELECT * FROM users WHERE id = " + id
    cursor = db.execute(query)

    rows = cursor.fetchall()
    db.close()

    return {"users": rows}


# ============================================================
# SQL INJECTION VARIANT 2
# F-string interpolation
# ============================================================

@app.get("/users/fstring")
def get_user_fstring(name: str):
    db = get_db()

    query = f"SELECT * FROM users WHERE name = '{name}'"
    cursor = db.execute(query)

    rows = cursor.fetchall()
    db.close()

    return {"users": rows}


# ============================================================
# SQL INJECTION VARIANT 3
# .format() string formatting
# ============================================================

@app.get("/users/format")
def get_user_format(email: str):
    db = get_db()

    query = "SELECT * FROM users WHERE email = '{}'".format(email)
    cursor = db.execute(query)

    rows = cursor.fetchall()
    db.close()

    return {"users": rows}


# ============================================================
# SQL INJECTION VARIANT 4
# % string formatting
# ============================================================

@app.get("/users/percent")
def get_user_percent(username: str):
    db = get_db()

    query = "SELECT * FROM users WHERE username = '%s'" % username
    cursor = db.execute(query)

    rows = cursor.fetchall()
    db.close()

    return {"users": rows}


# ============================================================
# PATH TRAVERSAL VARIANT 1
# os.path.join() without containment validation
# ============================================================

@app.get("/files/join")
def read_file_join(filename: str):
    file_path = os.path.join(BASE_DIR, filename)

    with open(file_path, "r") as file:
        content = file.read()

    return {"content": content}


# ============================================================
# PATH TRAVERSAL VARIANT 2
# Direct string concatenation
# ============================================================

@app.get("/files/concat")
def read_file_concat(filename: str):
    file_path = "files/" + filename

    with open(file_path, "r") as file:
        content = file.read()

    return {"content": content}


# ============================================================
# PATH TRAVERSAL VARIANT 3
# pathlib path construction without containment validation
# ============================================================

@app.get("/files/pathlib")
def read_file_pathlib(filename: str):
    file_path = BASE_DIR / filename

    content = file_path.read_text()

    return {"content": content}


# ============================================================
# PATH TRAVERSAL VARIANT 4
# Dynamic path inside FileResponse
# ============================================================

@app.get("/files/download")
def download_file(filename: str):
    file_path = os.path.join("files", filename)

    return FileResponse(file_path)


# ============================================================
# NORMAL SAFE ENDPOINT
# This should NOT be reported as vulnerable.
# ============================================================

@app.get("/users/safe")
def get_user_safe(id: int):
    db = get_db()

    query = "SELECT * FROM users WHERE id = ?"
    cursor = db.execute(query, (id,))

    rows = cursor.fetchall()
    db.close()

    return {"users": rows}


# ============================================================
# NORMAL SAFE PATH HANDLING
# This should NOT be reported as vulnerable.
# ============================================================

@app.get("/files/safe")
def read_file_safe(filename: str):
    base = BASE_DIR.resolve()
    requested = (base / filename).resolve()

    if not requested.is_relative_to(base):
        return {"error": "Invalid path"}

    return {"content": requested.read_text()}


# ============================================================
# DATABASE INITIALIZATION
# ============================================================

def initialize_database():
    db = get_db()

    db.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            name TEXT,
            email TEXT
        )
    """)

    existing = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]

    if existing == 0:
        db.executemany(
            """
            INSERT INTO users (username, name, email)
            VALUES (?, ?, ?)
            """,
            [
                ("alice", "Alice", "alice@example.com"),
                ("bob", "Bob", "bob@example.com"),
                ("charlie", "Charlie", "charlie@example.com"),
            ],
        )

    db.commit()
    db.close()


initialize_database()
