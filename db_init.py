import sqlite3
import os

DB_PATH = "Krisha.db"

def init_db(reset=False):
    if reset and os.path.exists(DB_PATH):
        os.remove(DB_PATH)

    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        password TEXT,
        score INTEGER DEFAULT 0,
        tab_switches INTEGER DEFAULT 0,
        ai_assisted INTEGER DEFAULT 0
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS challenges (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT,
        description TEXT,
        flag TEXT,
        points INTEGER,
        level TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS submissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        challenge_id INTEGER,
        correct INTEGER,
        solve_time REAL,
        attempts INTEGER,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    )
    """)

    challenges = [
        ("Basic Injection", "Can you use SQL injection to bypass login?", "CTF{sql_injection_master}", 100, "Easy"),
        ("XSS Attack", "Find the vulnerability in the comment section.", "CTF{xss_is_fun}", 200, "Medium"),
        ("Buffer Overflow", "Overflow the buffer to get the shell.", "CTF{buffer_overflow_king}", 500, "Hard"),
        ("Crypto Challenge", "Decrypt the following message.", "CTF{crypto_wizard}", 300, "Medium")
    ]

    c.execute("SELECT COUNT(*) FROM challenges")
    if c.fetchone()[0] == 0:
        c.executemany("INSERT INTO challenges (title, description, flag, points, level) VALUES (?, ?, ?, ?, ?)", challenges)

    conn.commit()
    conn.close()

if __name__ == "__main__":
    init_db(reset=True)
    print("Database created with correct schema and sample challenges.")
