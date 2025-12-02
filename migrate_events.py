import sqlite3
import os

DB_PATH = os.path.join("instance", "tenshiguard.db")

def migrate():
    if not os.path.exists(DB_PATH):
        print(f"❌ Database not found at {DB_PATH}")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        print("Adding 'mitigation' column to 'event' table...")
        cursor.execute("ALTER TABLE event ADD COLUMN mitigation TEXT")
        print("SUCCESS: Column 'mitigation' added successfully.")
    except sqlite3.OperationalError as e:
        if "duplicate column" in str(e).lower():
            print("⚠️ Column 'mitigation' already exists. Skipping.")
        else:
            print(f"❌ Error adding column: {e}")

    conn.commit()
    conn.close()

if __name__ == "__main__":
    migrate()
