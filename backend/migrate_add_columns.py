"""
One-time migration: add missing columns to firewall_devices.
Safe to run multiple times (checks before adding).
"""
import sqlite3

DB = "firewall_cleanup.db"

MIGRATIONS = [
    ("firewall_devices", "cp_management_type", "ALTER TABLE firewall_devices ADD COLUMN cp_management_type VARCHAR"),
    ("firewall_devices", "sync_interval_hours", "ALTER TABLE firewall_devices ADD COLUMN sync_interval_hours INTEGER"),
]

conn = sqlite3.connect(DB)
cur = conn.cursor()

for table, column, sql in MIGRATIONS:
    cur.execute(f"PRAGMA table_info({table})")
    existing = [row[1] for row in cur.fetchall()]
    if column not in existing:
        print(f"Adding column {table}.{column} ...")
        cur.execute(sql)
        print(f"  Done.")
    else:
        print(f"Column {table}.{column} already exists — skipping.")

conn.commit()
conn.close()
print("Migration complete.")
