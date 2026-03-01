import sqlite3

def cleanup():
    conn = sqlite3.connect("database.db")
    c = conn.cursor()

    # Find duplicates
    c.execute("""
        SELECT username, COUNT(*)
        FROM users
        GROUP BY username
        HAVING COUNT(*) > 1
    """)
    duplicates = c.fetchall()

    if not duplicates:
        print("No duplicates found.")
        conn.close()
        return

    print(f"Found {len(duplicates)} duplicate usernames.")

    for username, count in duplicates:
        print(f"Processing '{username}' (count: {count})...")
        
        # Get all users with this username, ordered by score DESC, then ID ASC
        # We want to keep the first one
        c.execute("""
            SELECT id, score 
            FROM users 
            WHERE username = ? 
            ORDER BY score DESC, id ASC
        """, (username,))
        users = c.fetchall()
        
        keep_user = users[0]
        delete_users = users[1:]
        
        print(f"  - Keeping ID: {keep_user[0]} (Score: {keep_user[1]})")
        
        for u in delete_users:
            uid = u[0]
            print(f"  - Deleting ID: {uid} (Score: {u[1]})")
            
            # Delete user
            c.execute("DELETE FROM users WHERE id = ?", (uid,))
            
            # Delete submissions for this user
            c.execute("DELETE FROM submissions WHERE user_id = ?", (uid,))
            
    conn.commit()
    print("Cleanup complete.")
    conn.close()

if __name__ == "__main__":
    cleanup()
