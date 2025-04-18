from io import StringIO
import csv
from datetime import datetime, date

from flask import (
    Response, request, render_template, flash, url_for, redirect
)
from sqlalchemy import func

from app.extensions import db
from .blueprint import superadmin_bp
from .decorators import superadmin_required
from .models.audit_logs import AuditLog


@superadmin_bp.route("/audit-logs", methods=["GET"], endpoint="audit_logs")
@superadmin_required
def audit_logs_view():
    """
    Display superadmin audit logs with filters, CSV export, and pagination.
    """

    # Grab query parameters from URL
    page       = request.args.get("page", 1, type=int)
    per_page   = 20
    action     = request.args.get("action")
    date_from  = request.args.get("date_from")
    date_to    = request.args.get("date_to")
    ip         = request.args.get("ip")
    search     = request.args.get("search")
    fmt        = request.args.get("format")

    # Static choices for the action filter dropdown
    action_choices = ["LOGIN", "LOGOUT", "CONFIG_CHANGE", "FAILED_LOGIN"]

    # Build the query for logs, most recent first
    query = AuditLog.query.order_by(AuditLog.timestamp.desc())

    # Apply filters if provided
    if action:
        query = query.filter(AuditLog.action == action)

    if date_from:
        try:
            from_date = datetime.strptime(date_from, "%Y-%m-%d")
            query = query.filter(AuditLog.timestamp >= from_date)
        except ValueError:
            pass  # Silently ignore bad input

    if date_to:
        try:
            to_date = datetime.strptime(date_to, "%Y-%m-%d")
            # Include the whole day by setting time to 23:59:59
            query = query.filter(AuditLog.timestamp <= to_date.replace(hour=23, minute=59, second=59))
        except ValueError:
            pass

    if ip:
        query = query.filter(AuditLog.ip_address.ilike(f"%{ip}%"))

    if search:
        query = query.filter(AuditLog.details.ilike(f"%{search}%"))

    # If CSV export is requested, return file download
    if fmt == "csv":
        logs = query.all()
        si = StringIO()
        writer = csv.writer(si)
        writer.writerow(["timestamp", "action", "details", "ip_address", "user_agent"])
        for log in logs:
            writer.writerow([
                log.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                log.action,
                log.details,
                log.ip_address,
                log.user_agent,
            ])
        output = si.getvalue()
        return Response(
            output,
            mimetype="text/csv",
            headers={
                "Content-Disposition": f"attachment; filename=audit_logs_{datetime.utcnow():%Y%m%d-%H%M}.csv"
            }
        )

    # Otherwise, show logs in a paginated web view
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    logs = pagination.items

    # Prepare filter values to preserve them across pagination & export
    filters = {
        "action": action or "",
        "date_from": date_from or "",
        "date_to": date_to or "",
        "ip": ip or "",
        "search": search or ""
    }

    return render_template(
        "superadmin/audit_logs.html",
        logs=logs,
        pagination=pagination,
        filters=filters,
        action_choices=action_choices,
        today=date.today().strftime("%Y-%m-%d"),
    )


@superadmin_bp.route("/audit-logs/clear", methods=["POST"], endpoint="clear_audit_logs")
@superadmin_required
def clear_audit_logs():
    """
    Wipe all audit logs from the database.
    """
    try:
        deleted = AuditLog.query.delete()
        db.session.commit()
        flash(f"Cleared {deleted} audit logs.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error clearing audit logs: {e}", "danger")

    return redirect(url_for("superadmin.audit_logs"))
