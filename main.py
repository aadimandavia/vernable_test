    #
    # User-controlled "id" flows directly into SQL.
    query = "SELECT * FROM users WHERE id = ?"

    cursor = db.execute(query, (id,))
    rows = cursor.fetchall()
