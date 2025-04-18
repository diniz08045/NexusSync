from datetime import datetime
from app.extensions import db


class EmailConfig(db.Model):
    """
    Stores SMTP server configuration for sending emails.

    This model lets you update email settings dynamically via the UI or admin panel
    instead of hardcoding them into environment variables or config files.
    """
    __tablename__ = "email_config"

    # Unique ID for the email config entry
    id = db.Column(db.Integer, primary_key=True)

    # SMTP server address (e.g., smtp.sendgrid.net)
    mail_server = db.Column(db.String(128), nullable=False)

    # Port number for SMTP (typically 587 for TLS or 465 for SSL)
    mail_port = db.Column(db.Integer, nullable=False)

    # Whether to use TLS encryption (recommended for most providers)
    mail_use_tls = db.Column(db.Boolean, default=True)

    # Whether to use SSL encryption (usually not needed if TLS is enabled)
    mail_use_ssl = db.Column(db.Boolean, default=False)

    # SMTP username (can be an email or API key depending on provider)
    mail_username = db.Column(db.String(128), nullable=False)

    # SMTP password or API key (⚠️ should be encrypted if stored)
    mail_password = db.Column(db.String(256), nullable=False)

    # Default "From" address for outgoing emails
    mail_default_sender = db.Column(db.String(128), nullable=False)

    # Timestamp of the last update to this config
    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )

    # User ID of the admin who last updated the settings
    updated_by = db.Column(db.Integer, db.ForeignKey("user.id"))

    def __repr__(self):
        return f"<EmailConfig {self.mail_server}:{self.mail_port}>"
