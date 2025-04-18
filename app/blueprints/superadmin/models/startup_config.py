from datetime import datetime
from app.extensions import db


class StartupConfig(db.Model):
    """
    Defines behavior for app initialization and startup automation.

    This config controls whether the app should auto-migrate the DB,
    create an admin account, auto-backup, and more when the app boots up.
    """
    __tablename__ = "startup_config"

    # Unique ID for the config row
    id = db.Column(db.Integer, primary_key=True)

    # Run automatic DB migrations at startup (Alembic-style or custom)
    auto_migrate = db.Column(db.Boolean, default=True)

    # Create a default admin user on first boot (if none exists)
    auto_create_admin = db.Column(db.Boolean, default=True)

    # Enable automatic backup job on startup (e.g., ZIP dump or cloud sync)
    auto_backup = db.Column(db.Boolean, default=False)

    # Start background services automatically (e.g., schedulers, GeoIP, WAF)
    auto_start_services = db.Column(db.Boolean, default=True)

    # Optional delay to wait for dependencies (like DB or Redis) before proceeding
    startup_timeout = db.Column(db.Integer, default=60)  # in seconds

    # Timestamp for the last update
    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )

    # Who last updated this setting
    updated_by = db.Column(db.Integer, db.ForeignKey("user.id"))

    def __repr__(self):
        return f"<StartupConfig Timeout:{self.startup_timeout}s>"
