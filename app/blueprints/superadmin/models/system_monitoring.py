from datetime import datetime
from app.extensions import db


class SystemMetric(db.Model):
    """
    Stores system performance metrics captured at a specific point in time.

    This model powers real-time or historical analytics dashboards by storing
    periodic measurements of CPU, memory, disk, database, and I/O pressure.
    """
    __tablename__ = "system_metric"

    # Unique ID for each metric sample
    id = db.Column(db.Integer, primary_key=True)

    # When this metric snapshot was recorded
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

    # CPU usage percentage at the time (e.g., 43.6%)
    cpu_percent = db.Column(db.Float)

    # Memory usage percentage (e.g., 74.2%)
    memory_percent = db.Column(db.Float)

    # Disk space used in GB (e.g., 120.4 GB)
    disk_used_gb = db.Column(db.Float)

    # Database size in megabytes (e.g., 250.7 MB)
    db_size_mb = db.Column(db.Float)

    # 5-minute load average (useful on Linux systems)
    cpu_load_5min = db.Column(db.Float)

    # Percentage of memory pressure (Linux-based metric for swap pressure)
    memory_pressure = db.Column(db.Float)

    # I/O wait time as a percentage (system waiting on disk access)
    io_wait_percent = db.Column(db.Float)

    def __repr__(self):
        return f"<SystemMetric {self.timestamp} CPU:{self.cpu_percent}% MEM:{self.memory_percent}%>"
