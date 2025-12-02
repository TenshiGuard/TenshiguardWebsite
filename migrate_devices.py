
import sqlite3
import os

DB_PATH = "f:/tenshiguard_ai/instance/tenshiguard.db"

def migrate_db():
    if not os.path.exists(DB_PATH):
        print(f"Database not found at {DB_PATH}")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        # Check if columns exist
        cursor.execute("PRAGMA table_info(device)")
        columns = [info[1] for info in cursor.fetchall()]

        if "risk_level" not in columns:
            print("Adding risk_level column...")
            cursor.execute("ALTER TABLE device ADD COLUMN risk_level TEXT DEFAULT 'low'")
        
        if "priority" not in columns:
            print("Adding priority column...")
            cursor.execute("ALTER TABLE device ADD COLUMN priority INTEGER DEFAULT 0")

        # Check alert table
        cursor.execute("PRAGMA table_info(alert)")
        alert_columns = [info[1] for info in cursor.fetchall()]
        
        if "device_id" not in alert_columns:
            print("Adding device_id column to alert table...")
            cursor.execute("ALTER TABLE alert ADD COLUMN device_id INTEGER REFERENCES device(id) ON DELETE SET NULL")

        conn.commit()
        print("Migration completed successfully.")
    except Exception as e:
        print(f"Migration failed: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    migrate_db()
