from fastapi import FastAPI
import sqlite3

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
# VULNERABILITY 1: SQL INJECTION (CWE-89)
# ============================================================

@app.get("/users")
def get_user(id: str):
    # INTENTIONALLY VULNERABLE
    query = "SELECT * FROM users WHERE id = " + id

    cursor = db.execute(query)
    rows = cursor.fetchall()

    return {
        "users": rows
    }


# ============================================================
# VULNERABILITY 2: API RESOURCE / COST EXHAUSTION (CWE-400)
# ============================================================

def expensive_external_api(prompt: str):
    """
    Simulates an expensive external AI/API operation.

    In the real application this could represent:
      - OpenAI
      - Anthropic
      - Google Gemini
      - another paid external API
    """

    # INTENTIONALLY EXPENSIVE OPERATION
    return {
        "result": "Processed expensive request",
        "input_length": len(prompt)
    }


@app.post("/api/chat")
def chat(prompt: str):
    # INTENTIONALLY VULNERABLE
    #
    # No:
    # - rate limiting
    # - authentication requirement
    # - input-size limit
    # - request quota
    # - abuse protection

    return expensive_external_api(prompt)
