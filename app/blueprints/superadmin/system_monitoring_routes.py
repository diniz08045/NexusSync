import os
import shutil
from datetime import datetime, timedelta

import psutil
from flask import abort, current_app, jsonify, render_template, request

from app.extensions import db
from .blueprint import superadmin_bp
from app.blueprints.superadmin.decorators import superadmin_required
from app.blueprints.superadmin.models.system_monitoring import SystemMetric


# ================================
# Route: System Monitoring Page
# ================================
@superadmin_bp.route("/system-monitoring", methods=["GET"], endpoint="system_monitoring")
@superadmin_required
def system_monitoring_view():
    """
    Renders the main system monitoring dashboard.
    Real-time metrics are fetched via AJAX on the frontend.
    """
    return render_template("superadmin/system_monitoring.html")


# ================================
# Route: Real-Time System Metrics
# ================================
@superadmin_bp.route("/system-metrics")
@superadmin_required
def system_metrics():
    """
    Returns real-time system resource usage as JSON.
    Includes CPU, memory, disk, DB size, and I/O wait.
    """
    try:
        # CPU usage percentage (1 sec interval)
        cpu_percent = psutil.cpu_percent(interval=1)

        # Memory usage (in MB and %)
        memory = psutil.virtual_memory()
        memory_used = memory.used // (1024 * 1024)
        memory_percent = memory.percent

        # Disk usage (in GB and %)
        disk = shutil.disk_usage("/")
        disk_used = disk.used // (1024 * 1024 * 1024)
        disk_percent = round((disk.used / disk.total) * 100, 2)

        # DB size (based on detected .db file in instance/)
        db_size_mb = 0.0
        try:
            db_path = current_app.instance_path
            db_file = next((f for f in os.listdir(db_path) if f.endswith(".db")), None)
            if db_file:
                full_db_path = os.path.join(db_path, db_file)
                if os.path.exists(full_db_path):
                    db_size_mb = os.path.getsize(full_db_path) / (1024 * 1024)
        except Exception as e:
            current_app.logger.error(f"Error calculating DB size: {e}")

        # CPU load average over 5 minutes (if supported)
        if hasattr(os, "getloadavg"):
            load_5min = os.getloadavg()[1]
            cpu_load_5min = (load_5min / (psutil.cpu_count() or 1)) * 100
        else:
            cpu_load_5min = None

        # I/O wait time
        cpu_times = psutil.cpu_times_percent(interval=1)
        io_wait_percent = getattr(cpu_times, "iowait", 0.0)

        return jsonify({
            "cpu_percent": cpu_percent,
            "memory_used": memory_used,
            "memory_percent": memory_percent,
            "disk_used": disk_used,
            "disk_percent": disk_percent,
            "db_size_mb": round(db_size_mb, 2),
            "cpu_load_5min": None if cpu_load_5min is None else round(cpu_load_5min, 2),
            "memory_pressure": memory_percent,
            "io_wait_percent": round(io_wait_percent, 2),
        })

    except Exception as e:
        current_app.logger.error(f"Error in system_metrics endpoint: {e}")
        return jsonify({"error": str(e)}), 500


# ================================
# Route: Historical Metrics
# ================================
@superadmin_bp.route("/system-metrics/history")
@superadmin_required
def system_metrics_history():
    """
    Returns historical system metrics (daily, weekly, or monthly)
    Aggregated for frontend chart visualization.
    """
    range_type = request.args.get("range", "day")
    now = datetime.utcnow()

    if range_type == "day":
        since = now - timedelta(days=1)
        interval_seconds = 3600  # 1 hour
    elif range_type == "week":
        since = now - timedelta(weeks=1)
        interval_seconds = 43200  # 12 hours
    elif range_type == "month":
        since = now - timedelta(days=30)
        interval_seconds = 86400  # 24 hours
    else:
        return abort(400, "Invalid range specified")

    metrics = (
        SystemMetric.query.filter(SystemMetric.timestamp >= since)
        .order_by(SystemMetric.timestamp.asc())
        .all()
    )

    def aggregate_data(metrics, interval):
        """Groups and averages metrics by interval."""
        aggregated = []
        group = []
        current_group_start = None

        for m in metrics:
            if current_group_start is None:
                current_group_start = m.timestamp
                group = [m]
            elif (m.timestamp - current_group_start).total_seconds() < interval:
                group.append(m)
            else:
                avg_cpu = sum(g.cpu_percent for g in group) / len(group)
                avg_mem = sum(g.memory_percent for g in group) / len(group)
                midpoint = current_group_start + (group[-1].timestamp - current_group_start) / 2
                aggregated.append({
                    "timestamp": midpoint.isoformat(),
                    "cpu_percent": avg_cpu,
                    "memory_percent": avg_mem,
                })
                current_group_start = m.timestamp
                group = [m]

        # Final group
        if group:
            avg_cpu = sum(g.cpu_percent for g in group) / len(group)
            avg_mem = sum(g.memory_percent for g in group) / len(group)
            midpoint = current_group_start + (group[-1].timestamp - current_group_start) / 2
            aggregated.append({
                "timestamp": midpoint.isoformat(),
                "cpu_percent": avg_cpu,
                "memory_percent": avg_mem,
            })

        return aggregated

    return jsonify(aggregate_data(metrics, interval_seconds))


# ================================
# Function: Log System Metrics
# ================================
def log_system_metrics():
    """
    Gathers and stores current system resource usage to DB.
    Intended to be run periodically by a background scheduler.
    """
    print("[DEBUG] log_system_metrics() was called")

    try:
        # Disk usage
        disk = shutil.disk_usage("/")
        disk_used_gb = disk.used / (1024**3)
        print(f"[DEBUG] Disk used: {disk_used_gb:.2f} GB")

        # DB size
        db_path = os.path.join(os.getcwd(), "instance")
        db_file = next((f for f in os.listdir(db_path) if f.endswith(".db")), None)
        full_db_path = os.path.join(db_path, db_file) if db_file else None
        db_size_mb = os.path.getsize(full_db_path) // (1024 * 1024) if full_db_path and os.path.exists(full_db_path) else 0
        print(f"[DEBUG] DB size: {db_size_mb} MB")

        # CPU & memory
        cpu_percent = psutil.cpu_percent(interval=None)
        memory = psutil.virtual_memory()
        memory_percent = memory.percent
        print(f"[DEBUG] CPU: {cpu_percent}% | Memory: {memory_percent}%")

        # 5-min CPU load average
        try:
            cpu_load_5min = os.getloadavg()[1]
            print(f"[DEBUG] CPU load (5 min): {cpu_load_5min}")
        except (AttributeError, OSError):
            cpu_load_5min = 0.0
            print("[DEBUG] CPU load (5 min) not supported on this platform")

        # I/O wait
        cpu_times = psutil.cpu_times_percent(interval=None)
        io_wait_percent = getattr(cpu_times, "iowait", 0.0)
        print(f"[DEBUG] I/O wait: {io_wait_percent}%")

        # Save metrics to DB
        metric = SystemMetric(
            timestamp=datetime.utcnow(),
            cpu_percent=cpu_percent,
            memory_percent=memory_percent,
            disk_used_gb=disk_used_gb,
            db_size_mb=db_size_mb,
            cpu_load_5min=cpu_load_5min,
            memory_pressure=memory_percent,
            io_wait_percent=io_wait_percent,
        )

        print("[DEBUG] Adding metric to database...")
        db.session.add(metric)
        db.session.commit()
        print("[SUCCESS] Metric committed to database.")

    except Exception as e:
        db.session.rollback()
        print(f"[ERROR] Failed to log system metrics: {e}")


# ================================
# Route: Manual Logging Trigger
# ================================
@superadmin_bp.route("/system-metrics/log-now")
@superadmin_required
def log_metric_now():
    """
    Manually triggers metric collection and DB storage.
    Useful for testing or one-time snapshots.
    """
    log_system_metrics()
    return jsonify({"status": "logged"})
