import sqlite3
conn = sqlite3.connect("firewall_cleanup.db")
cur = conn.cursor()
cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = [row[0] for row in cur.fetchall()]
print("Tables:", tables)
cur.execute("PRAGMA table_info(firewall_devices)")
cols = cur.fetchall()
print("\nfirewall_devices columns:")
for c in cols:
    print(" ", c[1], c[2])
conn.close()
