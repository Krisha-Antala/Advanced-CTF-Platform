import sqlite3

con = sqlite3.connect("database.db")
cur = con.cursor()

try:
    cur.execute("ALTER TABLE submissions ADD COLUMN solve_time REAL")
    print("Added solve_time column")
except:
    print("solve_time already exists")

try:
    cur.execute("ALTER TABLE submissions ADD COLUMN attempts INTEGER DEFAULT 1")
    print("Added attempts column")
except:
    print("attempts already exists")

con.commit()
con.close()
print("Database updated successfully")
