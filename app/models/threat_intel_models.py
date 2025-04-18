from datetime import datetime
from app.extensions import db  # Shared SQLAlchemy instance


# ================================
# Model: ThreatIntelEntry
# ================================
class ThreatIntelEntry(db.Model):
    """
    Stores raw threat intelligence data associated with an IP address.
    This includes threat category, source system, and confidence level.
    """

    __tablename__ = "threat_intel_entry"

    id = db.Column(db.Integer, primary_key=True)

    # IP address flagged (IPv4 or IPv6)
    ip_address = db.Column(db.String(45), nullable=False)

    # Type of threat (e.g., malware, botnet, phishing)
    threat_type = db.Column(db.String(128), nullable=False)

    # Source of the threat data (e.g., AbuseIPDB, Spamhaus, internal)
    source = db.Column(db.String(128), nullable=False)

    # Confidence score between 0.0 and 1.0
    confidence_score = db.Column(db.Float, nullable=False)

    # Extended metadata (e.g., context, history, notes) in JSON/text form
    threat_metadata = db.Column(db.Text)

    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)

    def to_dict(self):
        """Returns a serializable dictionary representation of the threat entry."""
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "threat_type": self.threat_type,
            "source": self.source,
            "confidence_score": self.confidence_score,
            "threat_metadata": self.threat_metadata,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


# ================================
# Model: GeoIPBlock
# ================================
class GeoIPBlock(db.Model):
    """
    Represents a country-level block based on GeoIP data.
    Used to restrict access from specific countries (e.g., high-risk zones).
    """

    __tablename__ = "geoip_block"

    id = db.Column(db.Integer, primary_key=True)

    # ISO 3166-1 alpha-2 country code (e.g., "US", "CN")
    country_code = db.Column(db.String(3), nullable=False, unique=True)

    # Reason for blocking the country
    reason = db.Column(db.String(256))

    # Indicates whether this was set manually or by automated logic
    updated_by = db.Column(db.String(50))

    # When the block was created
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def to_dict(self):
        """Serialize as dictionary for JSON use."""
        return {
            "id": self.id,
            "country_code": self.country_code,
            "reason": self.reason,
            "updated_by": self.updated_by,
            "created_at": self.created_at.isoformat(),
        }


# ================================
# Model: ASNBlock
# ================================
class ASNBlock(db.Model):
    """
    Represents a block based on Autonomous System Number (ASN).
    Useful for banning entire organizations or hosting providers.
    """

    __tablename__ = "asn_block"

    id = db.Column(db.Integer, primary_key=True)

    # ASN identifier (e.g., 15169 for Google)
    asn = db.Column(db.Integer, nullable=False, unique=True)

    # Associated organization (optional)
    organization = db.Column(db.String(256))

    # Reason for blocking this ASN
    reason = db.Column(db.String(256))

    # When the ASN block was added
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def to_dict(self):
        """Convert to dictionary for use in APIs or templates."""
        return {
            "id": self.id,
            "asn": self.asn,
            "organization": self.organization,
            "reason": self.reason,
            "created_at": self.created_at.isoformat(),
        }


# ================================
# Model: HoneypotEvent
# ================================
class HoneypotEvent(db.Model):
    """
    Logs traffic and interactions with honeypot traps.
    Used for detecting scanning, intrusion attempts, and other malicious probes.
    """

    __tablename__ = "honeypot_event"

    id = db.Column(db.Integer, primary_key=True)

    # Attacker IP
    ip_address = db.Column(db.String(45), nullable=False)

    # Type of interaction detected (e.g., SSH brute force, HTTP probe)
    event_type = db.Column(db.String(128), nullable=False)

    # Raw details (can store JSON, payloads, headers, etc.)
    details = db.Column(db.Text)

    # When the event occurred
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)

    def to_dict(self):
        """Output honeypot data for external processing or dashboarding."""
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "event_type": self.event_type,
            "details": self.details,
            "created_at": self.created_at.isoformat(),
        }
