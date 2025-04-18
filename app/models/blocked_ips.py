# app/models/blocked_ip_range.py

from datetime import datetime
from app.extensions import db


class BlockedIPRange(db.Model):
    """
    Represents a blocked IP address or CIDR range in the system.
    Used to prevent connections from known malicious networks or unwanted sources.
    """

    __tablename__ = "blocked_ip_ranges"

    # Primary key ID for this record
    id = db.Column(db.Integer, primary_key=True)

    # IP or CIDR block to be denied access (e.g., "203.0.113.0/24")
    network = db.Column(db.String(50), unique=True, nullable=False)

    # Reason for blocking this IP range (optional, e.g., "Spamhaus DROP", "Abuse complaint")
    reason = db.Column(db.String(255), nullable=True)

    # Indicates who or what updated this entry ("manual", "auto", system user, etc.)
    updated_by = db.Column(db.String(50), nullable=True)

    # When the entry was created (UTC)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    # When the entry was last modified (UTC)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def to_dict(self):
        """
        Converts the model instance to a dictionary for easy JSON serialization.
        Commonly used in APIs and logging.
        """
        return {
            "network": self.network,
            "reason": self.reason,
            "updated_by": self.updated_by,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
        }
