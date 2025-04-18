from datetime import datetime
from app.extensions import db

class AuditLog(db.Model):
    """
    Represents an audit trail entry for user or system actions.
    Used for security monitoring, accountability, and system debugging.
    """
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)

    # Reference to the user who performed the action (can be null for system events)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)

    # The type of action performed (e.g., LOGIN, CONFIG_CHANGE)
    action = db.Column(db.String(64), nullable=False)

    # Descriptive details about what happened
    details = db.Column(db.Text)

    # The IP address from which the action originated
    ip_address = db.Column(db.String(45))  # IPv6 compatible

    # The full user-agent string from the request
    user_agent = db.Column(db.Text)

    # Timestamp of when the action occurred
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<AuditLog {self.action} at {self.timestamp}>"
