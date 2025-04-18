from datetime import datetime

from app.extensions import db
from app.blueprints.superadmin.config_keys import ConfigKeys

# Optional: casting rules for config values depending on their type
CONFIG_CASTS = {
    # Booleans
    ConfigKeys.DEBUG_MODE: lambda v: str(v).strip().lower() in ["true", "1", "enabled"],
    ConfigKeys.MAINTENANCE_MODE: lambda v: str(v).strip().lower() in ["true", "1", "enabled"],

    # Integers
    ConfigKeys.SESSION_TIMEOUT_MINUTES: lambda v: int(v) if str(v).isdigit() else 30,

    # Strings
    ConfigKeys.TIMEZONE: lambda v: v,  # No casting needed, stored as-is
}


class SystemConfig(db.Model):
    """
    Stores dynamic system-wide configuration settings.

    Each setting is a key/value pair stored in the database and can be
    loaded into `app.config` at runtime (with casting support via CONFIG_CASTS).
    """
    __tablename__ = "system_config"

    # Unique ID for each config entry
    id = db.Column(db.Integer, primary_key=True)

    # Config key name (e.g., "DEBUG_MODE", "APPLICATION_NAME")
    key = db.Column(db.String(128), unique=True, nullable=False)

    # Stored value (always stored as a string, casted as needed when loaded)
    value = db.Column(db.Text, nullable=False)

    # Timestamp for last update
    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )

    # Optional: ID of the user who last updated this config
    updated_by = db.Column(db.Integer, db.ForeignKey("user.id"))

    def __repr__(self):
        return f"<SystemConfig {self.key}: {self.value}>"
