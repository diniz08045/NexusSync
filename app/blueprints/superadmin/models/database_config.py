from datetime import datetime
from app.extensions import db


class DatabaseConfig(db.Model):
    """
    Stores external or alternative database connection settings.

    This can be used for connecting to separate analytics, backup, or legacy databases.
    You could extend this to support multiple environments or services.
    """
    __tablename__ = "database_config"

    # Unique identifier for each config record
    id = db.Column(db.Integer, primary_key=True)

    # Hostname or IP address of the database server
    db_host = db.Column(db.String(128), nullable=False)

    # Port number (typically 5432 for PostgreSQL, 3306 for MySQL, etc.)
    db_port = db.Column(db.Integer, nullable=False)

    # Name of the specific database/schema to connect to
    db_name = db.Column(db.String(128), nullable=False)

    # Username used for authentication
    db_user = db.Column(db.String(128), nullable=False)

    # Password for the user (NOTE: consider encrypting this at rest)
    db_password = db.Column(db.String(256), nullable=False)

    # Timestamp of the last time this config was updated
    updated_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow
    )

    # Admin user ID who made the update
    updated_by = db.Column(db.Integer, db.ForeignKey("user.id"))

    def __repr__(self):
        return f"<DatabaseConfig {self.db_name} on {self.db_host}:{self.db_port}>"
