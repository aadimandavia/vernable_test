def get_user(id: str):
    # INTENTIONALLY VULNERABLE
    query = "SELECT * FROM users WHERE id = ?"

    cursor = db.execute(query, (id,))
    rows = cursor.fetchall()
