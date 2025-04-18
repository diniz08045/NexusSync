from datetime import datetime
from app.extensions import db


class LoginAttempt(db.Model):
    """
    Represents an attempt to log in to the system.
    Tracks both successful and failed attempts for auditing and security monitoring.
    """

    __tablename__ = "login_attempts"

    # Unique ID for the attempt
    id = db.Column(db.Integer, primary_key=True)

    # Reference to the user making the attempt
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    # IP address of the requester (supports IPv4 and IPv6)
    ip_address = db.Column(db.String(45))

    # Full user-agent string from the request header
    user_agent = db.Column(db.String(256))

    # Timestamp of when the attempt occurred (UTC)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    # Was the attempt successful or not?
    successful = db.Column(db.Boolean, default=False)

    def __repr__(self):
        """Developer-friendly string representation of the login attempt."""
        status = "successful" if self.successful else "failed"
        return f"<LoginAttempt {status} for user_id {self.user_id} at {self.timestamp}>"
