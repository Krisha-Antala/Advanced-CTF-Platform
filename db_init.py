import sqlite3
import os

# Remove old DB if exists to ensure clean slate with new schema
if os.path.exists("database.db"):
    os.remove("database.db")

conn = sqlite3.connect("database.db")
c = conn.cursor()

# Users Table
c.execute("""
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password TEXT,
    score INTEGER DEFAULT 0
)
""")

# Challenges Table
# Schema inferred: 0:id, 1:title, 2:description, 3:flag, 4:points, 5:level
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

# Submissions Table
# Schema inferred from app.py: user_id, challenge_id, correct, solve_time, attempts
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

# Insert Sample Challenges
challenges = [
    ("Basic Injection", "Can you use SQL injection to bypass login?", "CTF{sql_injection_master}", 100, "Easy"),
    ("XSS Attack", "Find the vulnerability in the comment section.", "CTF{xss_is_fun}", 200, "Medium"),
    ("Buffer Overflow", "Overflow the buffer to get the shell.", "CTF{buffer_overflow_king}", 500, "Hard"),
    ("Crypto Challenge", "Decrypt the following message.", "CTF{crypto_wizard}", 300, "Medium")
]

c.executemany("INSERT INTO challenges (title, description, flag, points, level) VALUES (?, ?, ?, ?, ?)", challenges)

conn.commit()
conn.close()

print("Database created with correct schema and sample challenges.")
