from datetime import datetime
from app.extensions import db


class PasswordHistory(db.Model):
    """
    Tracks historical password hashes for a user.

    This helps enforce policies like "prevent reuse of last 5 passwords",
    and provides traceability for password changes (manual or automated).
    """
    __tablename__ = "password_history"

    # Unique identifier for each password change record
    id = db.Column(db.Integer, primary_key=True)

    # Link to the user this password belongs to (cannot be null)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    # Hashed version of the user's previous password
    password_hash = db.Column(db.String(256), nullable=False)

    # When the password was changed
    changed_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Optional note or reason (e.g., "manual change", "forced reset", "expired")
    change_reason = db.Column(db.Text)

    def __repr__(self):
        return f"<PasswordHistory User:{self.user_id} Changed:{self.changed_at}>"
