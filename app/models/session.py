from datetime import datetime
from app.extensions import db


class SessionActivity(db.Model):
    """
    Tracks user session activity for auditing and session management.
    Stores metadata like IP, user agent, and session ID to detect suspicious behavior.
    """

    __tablename__ = "session_activity"

    # Unique session activity ID
    id = db.Column(db.Integer, primary_key=True)

    # ID of the user this session belongs to
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    # Unique session identifier (e.g., stored in cookie)
    session_id = db.Column(db.String(128), nullable=False, index=True)

    # IP address from which the session was initiated
    ip_address = db.Column(db.String(45), nullable=False)  # Supports IPv6

    # User agent string from the browser/client
    user_agent = db.Column(db.String(256), nullable=False)

    # Timestamp when the session was first created
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Last time this session was active (used for timeouts or tracking)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)

    # Indicates whether the session is still active (e.g., logged in)
    is_active = db.Column(db.Boolean, default=True)

    # Relationship to the User model (backref allows access via user.sessions)
    user = db.relationship("User", backref=db.backref("sessions", lazy="dynamic"))

    def __repr__(self):
        """Developer-friendly string representation for debugging."""
        return f"<SessionActivity {self.session_id}>"
