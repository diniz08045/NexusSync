from datetime import datetime
from app.extensions import db


class IPManagement(db.Model):
    """
    Represents a managed IP rule — either allowed or blocked.

    This can be used for IP whitelisting, blacklisting, rate limiting exceptions,
    or firewall integration. CIDR blocks are supported as well.
    """
    __tablename__ = "ip_management"

    # Unique ID for each IP entry
    id = db.Column(db.Integer, primary_key=True)

    # IP address or CIDR range (e.g., '192.168.0.1' or '10.0.0.0/24')
    ip_address = db.Column(db.String(45), nullable=False)

    # Status flag: "allowed", "blocked", or custom (enforce with validation)
    status = db.Column(db.String(16), nullable=False)

    # Optional description or reason for the rule (e.g., "Suspicious activity", "VPN bypass")
    reason = db.Column(db.Text)

    # When this rule was created
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # When this rule was last modified
    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )

    # ID of the admin who last edited the entry
    updated_by = db.Column(db.Integer, db.ForeignKey("user.id"))

    def __repr__(self):
        return f"<IPManagement {self.ip_address} {self.status}>"
