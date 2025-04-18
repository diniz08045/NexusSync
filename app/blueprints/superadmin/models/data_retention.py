from datetime import datetime
from app.extensions import db


class DataRetention(db.Model):
    """
    Stores system-wide retention policy settings.

    This table defines how long different types of data should be kept
    before being purged, helping to comply with privacy policies or storage limits.
    """
    __tablename__ = "data_retention"

    # Unique identifier for the retention policy entry
    id = db.Column(db.Integer, primary_key=True)

    # Number of days to keep audit or activity logs
    log_retention_days = db.Column(db.Integer, nullable=False)

    # Number of days to retain system/database backups
    backup_retention_days = db.Column(db.Integer, nullable=False)

    # Number of days to keep user-related data (e.g., after account deletion)
    user_data_retention_days = db.Column(db.Integer, nullable=False)

    # When the retention policy was last updated
    updated_at = db.Column(
        db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow
    )

    # User ID of the admin who last updated the policy
    updated_by = db.Column(db.Integer, db.ForeignKey("user.id"))

    def __repr__(self):
        return f"<DataRetention logs:{self.log_retention_days} days>"
