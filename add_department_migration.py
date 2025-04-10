import os
# Import the app instance from app.py file
from app import db
import sys
# Add the current directory to the path to import app.py
sys.path.append('.')
from app import app

# Set up the Flask application context
with app.app_context():
    # Execute the SQL to add the department column if it doesn't exist
    print("Adding department column to user table...")
    try:
        db.session.execute('ALTER TABLE "user" ADD COLUMN IF NOT EXISTS department VARCHAR(64) DEFAULT \'default\'')
        db.session.execute('CREATE INDEX IF NOT EXISTS ix_user_department ON "user" (department)')
        db.session.commit()
        print("Migration successful: department column added to user table")
    except Exception as e:
        db.session.rollback()
        print(f"Error during migration: {e}")