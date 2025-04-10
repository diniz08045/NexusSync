import sys
sys.path.append('.')
from app import db
import app as app_module
app = app_module.app
from models import User

# Find all users and add department if missing
with app.app_context():
    # Update existing users to have default department if they don't have one
    users = User.query.all()
    print(f"Found {len(users)} users")
    
    for user in users:
        if not user.department:
            user.department = 'default'
            print(f"Updated user {user.username} with default department")
    
    # Commit changes
    db.session.commit()
    print("Database updated successfully")