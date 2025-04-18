from datetime import datetime
from flask import (
    flash, redirect, render_template, request, url_for, Response
)
from flask_login import current_user
from io import StringIO
import csv

from app.extensions import db
from .blueprint import superadmin_bp
from .decorators import superadmin_required, log_action
from .forms import IPManagementForm
from .models.ip_management import IPManagement
from .models.audit_logs import AuditLog

# Security intelligence modules
from app.security.intelligence.spamhaus import fetch_spamhaus_drop_list
from app.security.intelligence.blocklist import rules_engine, BlocklistRule
from app.security.intelligence.geoip import geoip_manager
from app.security.intelligence.correlation import correlation_engine
from app.security.intelligence.scanning import honeypot_monitor, port_scanner


# -------------------------------
# Route: IP Management Dashboard
# -------------------------------
@superadmin_bp.route("/ip-management", methods=["GET", "POST"], endpoint="ip_management")
@superadmin_required
def ip_management_view():
    """
    Superadmin interface for managing IP whitelists, blacklists,
    and analyzing suspicious IP activity.

    Features:
    - Apply Spamhaus DROP list
    - Manually manage whitelist/blacklist
    - View recent login attempts
    - Live lookup (GeoIP, ASN, honeypot, correlation, scanning)
    """
    form = IPManagementForm()

    # --- 1. Handle "Block DROP List" request ---
    if request.method == "POST" and request.form.get("block_drop"):
        try:
            raw_drop = fetch_spamhaus_drop_list()
            count = 0
            for net in raw_drop:
                cidr = str(net)
                # Avoid re-adding already-blocked networks
                if not IPManagement.query.filter_by(ip_address=cidr, status="blocked").first():
                    db.session.add(IPManagement(
                        ip_address=cidr,
                        status="blocked",
                        updated_by=current_user.id
                    ))
                    count += 1
            db.session.commit()
            flash(f"Blocked {count} networks from Spamhaus DROP.", "success")
        except Exception as e:
            db.session.rollback()
            flash(f"Error blocking DROP list: {e}", "danger")
        return redirect(url_for("superadmin.ip_management"))

    # --- 2. Handle manual whitelist/blacklist form submission ---
    if form.validate_on_submit() and not request.form.get("block_drop"):
        try:
            IPManagement.query.delete()  # Clear previous entries
            wl = [ip.strip() for ip in form.whitelist.data.splitlines() if ip.strip()]
            bl = [ip.strip() for ip in form.blacklist.data.splitlines() if ip.strip()]

            # Add whitelisted IPs
            for ip in wl:
                db.session.add(IPManagement(ip_address=ip, status="allowed", updated_by=current_user.id))

            # Add blacklisted IPs
            for ip in bl:
                db.session.add(IPManagement(ip_address=ip, status="blocked", updated_by=current_user.id))

            db.session.commit()
            log_action("IP_CONFIG_CHANGE", f"Whitelist={wl}, Blacklist={bl}")
            flash("IP settings updated.", "success")
            return redirect(url_for("superadmin.ip_management"))

        except Exception as e:
            db.session.rollback()
            flash(f"Error updating settings: {e}", "danger")

    # --- 3. Pre-populate the form with current whitelist/blacklist from DB ---
    allowed = IPManagement.query.filter_by(status="allowed").all()
    blocked = IPManagement.query.filter_by(status="blocked").all()
    form.whitelist.data = "\n".join(e.ip_address for e in allowed)
    form.blacklist.data = "\n".join(e.ip_address for e in blocked)

    # --- 4. Load the latest Spamhaus DROP list (for viewing only) ---
    try:
        raw_drop = fetch_spamhaus_drop_list()
        drop_list = [str(net) for net in raw_drop]
    except Exception:
        drop_list = []

    # --- 5. Show recent login attempts from the audit logs ---
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(5).all()
    recent_attempts = []
    for log in logs:
        recent_attempts.append({
            "ip": log.ip_address or "—",
            "note": log.details or "",
            "status": "Allowed" if log.action == "LOGIN" else "Blocked" if log.action == "FAILED_LOGIN" else "Info",
        })

    # --- 6. Process tab-based tools like GeoIP/ASN/Correlation/Scan ---
    tab = request.args.get("tab") or "drop"
    lookup_ip = request.args.get("ip", "")
    lookup_result = None
    rules = []

    if tab == "geoip" and lookup_ip:
        lookup_result = geoip_manager.get_ip_location(lookup_ip)

    elif tab == "asn" and lookup_ip:
        lookup_result = geoip_manager.get_ip_asn(lookup_ip)

    elif tab == "correlate" and lookup_ip:
        lookup_result = correlation_engine.correlate_ip(lookup_ip)

    elif tab == "scan" and lookup_ip:
        lookup_result = port_scanner.scan_ip(lookup_ip)

    elif tab == "honeypot":
        hours = request.args.get("hours", 24, type=int)
        lookup_result = honeypot_monitor.get_recent_events(hours=hours)

    elif tab == "evaluate" and lookup_ip:
        lookup_result = rules_engine.evaluate_ip(lookup_ip)

    elif tab == "rules":
        rules = rules_engine.get_rules()

    return render_template(
        "superadmin/ip_management.html",
        form=form,
        drop_list=drop_list,
        recent_attempts=recent_attempts,
        tab=tab,
        lookup_ip=lookup_ip,
        lookup_result=lookup_result,
        rules=rules
    )


# -------------------------------
# Route: Download DROP List
# -------------------------------
@superadmin_bp.route("/ip-management/download-drop", methods=["GET"], endpoint="download_drop_list")
@superadmin_required
def download_drop_list():
    """
    Downloads the full Spamhaus DROP list as a plain text file.
    Allows admins to export the latest IP blocks for external tools.
    """
    try:
        raw_drop = fetch_spamhaus_drop_list()
        payload = "\n".join(str(net) for net in raw_drop)
    except Exception:
        payload = ""

    # Prepare the plain text response
    resp = Response(payload, mimetype="text/plain")
    resp.headers["Content-Disposition"] = 'attachment; filename="spamhaus_drop.txt"'
    return resp
