from fastapi import FastAPI
import sqlite3

app = FastAPI()

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


@app.get("/users")
def get_user(id: str):
    # INTENTIONALLY VULNERABLE
    query = "SELECT * FROM users WHERE id = " + id

    cursor = db.execute(query)
    rows = cursor.fetchall()

    return {
        "users": rows
    }

@app.post("/api/chat")
def chat(prompt: str):
    return expensive_external_api(prompt)
