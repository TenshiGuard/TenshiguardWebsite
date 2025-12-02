import sqlite3
import os

DB_PATH = r"f:\tenshiguard_ai\instance\tenshiguard.db"

def update_schema():
    if not os.path.exists(DB_PATH):
        print(f"Database not found at {DB_PATH}")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    try:
        # Check if columns exist
        cursor.execute("PRAGMA table_info(alert)")
        columns = [info[1] for info in cursor.fetchall()]

        if "feedback" not in columns:
            print("Adding 'feedback' column...")
            cursor.execute("ALTER TABLE alert ADD COLUMN feedback VARCHAR(20) DEFAULT 'pending'")
        
        if "feedback_at" not in columns:
            print("Adding 'feedback_at' column...")
            cursor.execute("ALTER TABLE alert ADD COLUMN feedback_at DATETIME")

        if "adjusted_score" not in columns:
            print("Adding 'adjusted_score' column...")
            cursor.execute("ALTER TABLE alert ADD COLUMN adjusted_score FLOAT DEFAULT 0.0")

        conn.commit()
        print("Database schema updated successfully.")

    except Exception as e:
        print(f"Error updating schema: {e}")
    finally:
        conn.close()

if __name__ == "__main__":
    update_schema()
