from datetime import datetime
from app.extensions import db


class SecurityConfig(db.Model):
    """
    Stores core security-related toggles for the application.

    This config allows dynamic control over SSL enforcement, WAF, proxy usage, and CORS settings,
    giving admins centralized control over key security features.
    """
    __tablename__ = "security_config"

    # Primary key for each config record
    id = db.Column(db.Integer, primary_key=True)

    # Whether to enforce HTTPS (used with Flask-Talisman or redirects)
    ssl_enabled = db.Column(db.Boolean, default=True)

    # Whether to route requests through a proxy (e.g. for reverse proxy setups)
    proxy_enabled = db.Column(db.Boolean, default=False)

    # If proxy is enabled, store the proxy server hostname or IP
    proxy_server = db.Column(db.String(128))

    # Port number to use with the proxy server
    proxy_port = db.Column(db.Integer)

    # Enable/disable the built-in WAF or threat detection layer
    waf_enabled = db.Column(db.Boolean, default=True)

    # Whether to enable Cross-Origin Resource Sharing
    cors_enabled = db.Column(db.Boolean, default=True)

    # List of allowed CORS origins (can be stored as a newline-delimited string or JSON array)
    cors_allowed_origins = db.Column(db.Text)

    # Timestamp for when this configuration was last modified
    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )

    # ID of the admin user who last updated this config
    updated_by = db.Column(db.Integer, db.ForeignKey("user.id"))

    def __repr__(self):
        return f"<SecurityConfig SSL:{self.ssl_enabled} WAF:{self.waf_enabled}>"
