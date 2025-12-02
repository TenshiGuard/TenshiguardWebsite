from app import create_app
from app.extensions import db
from sqlalchemy import text

def add_column():
    app = create_app()
    with app.app_context():
        print("Adding source_ip column to event table...")
        try:
            with db.engine.connect() as conn:
                conn.execute(text("ALTER TABLE event ADD COLUMN source_ip VARCHAR(50)"))
                conn.commit()
            print("Column added successfully.")
        except Exception as e:
            print(f"Error (column might already exist): {e}")

if __name__ == "__main__":
    add_column()
