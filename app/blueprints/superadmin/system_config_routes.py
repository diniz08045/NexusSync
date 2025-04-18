import json
import os
import secrets
import sys
from datetime import datetime
from pytz import timezone

from flask import Response, flash, redirect, render_template, request, url_for, current_app
from flask_login import current_user

from app.extensions import db
from .blueprint import superadmin_bp
from .config_keys import ConfigKeys
from .decorators import superadmin_required
from .forms import ConfigForm, SystemTimeForm
from .logger import logger
from .models.system_config import SystemConfig
from app.blueprints.superadmin.forms import CSRFOnlyForm


# ================================
# Route: System Configuration Page
# ================================
@superadmin_bp.route("/system-config", methods=["GET", "POST"], endpoint="system_config")
@superadmin_required
def system_config_view():
    """
    Display and manage system-wide settings.
    Allows editing of general app settings and timezone.
    Pulls values from DB and environment variables.
    """
    form = CSRFOnlyForm()
    config_form = ConfigForm()
    time_form = SystemTimeForm()

    tz_key = ConfigKeys.TIMEZONE
    tz_value = current_app.config.get(tz_key, "UTC")
    localized_now = datetime.now(timezone(tz_value))

    if request.method == "POST":
        # ----- General Config Form Submission -----
        if "config_submit" in request.form and config_form.validate_on_submit():
            updates = {
                ConfigKeys.APPLICATION_NAME: config_form.app_name.data,
                ConfigKeys.DEBUG_MODE: str(config_form.debug_mode.data),
                ConfigKeys.MAINTENANCE_MODE: str(config_form.maintenance_mode.data),
            }
            for key, value in updates.items():
                cfg = SystemConfig.query.filter_by(key=key).first()
                if cfg:
                    cfg.value = value
                    cfg.updated_at = datetime.utcnow()
                else:
                    db.session.add(SystemConfig(key=key, value=value, updated_by=current_user.id))
            db.session.commit()
            flash("System configuration updated.", "success")
            return redirect(url_for("superadmin.system_config"))

        # ----- Timezone Config Form Submission -----
        elif "time_submit" in request.form and time_form.validate_on_submit():
            try:
                key = ConfigKeys.TIMEZONE
                value = time_form.timezone.data
                cfg = SystemConfig.query.filter_by(key=key).first()
                if cfg:
                    cfg.value = value
                    cfg.updated_at = datetime.utcnow()
                else:
                    db.session.add(SystemConfig(key=key, value=value, updated_by=current_user.id))
                db.session.commit()
                current_app.config[key] = value
                flash("System time settings updated successfully.", "success")
                return redirect(url_for("superadmin.system_config"))
            except Exception as e:
                db.session.rollback()
                logger.error(f"Error updating timezone: {e}")
                flash(f"Error updating system time: {e}", "danger")

    else:
        # ----- Populate Forms on GET -----
        def get_value(k, default=None):
            cfg = SystemConfig.query.filter_by(key=k).first()
            return cfg.value if cfg else default

        def get_bool(k):
            val = get_value(k, str(current_app.config.get(k, False)))
            return val.lower() in ("true", "1", "enabled")

        config_form.app_name.data = get_value(ConfigKeys.APPLICATION_NAME, current_app.config.get(ConfigKeys.APPLICATION_NAME))
        config_form.debug_mode.data = get_bool(ConfigKeys.DEBUG_MODE)
        config_form.maintenance_mode.data = get_bool(ConfigKeys.MAINTENANCE_MODE)
        time_form.timezone.data = get_value(ConfigKeys.TIMEZONE, current_app.config.get(ConfigKeys.TIMEZONE))

    # Prepare display of DB + ENV settings
    env_keys = ["FLASK_ENV", "FLASK_APP", "DATABASE_URL", "SESSION_SECRET"]
    db_configs = SystemConfig.query.order_by(SystemConfig.key).all()
    env_configs = [
        SystemConfig(key=ek, value=os.environ.get(ek, "[not set]"), updated_at=None)
        for ek in env_keys
    ]
    config_env = {ek: os.environ.get(ek, "[not set]") for ek in env_keys}

    return render_template(
        "superadmin/system_config.html",
        config_form=config_form,
        time_form=time_form,
        form=form,
        configs=db_configs + env_configs,
        config_env=config_env,
        now=localized_now,
        tz_value=tz_value,
        datetime=datetime
    )
# ================================
# Route: Reset All Configurations
# ================================
@superadmin_bp.route("/system-config/reset", methods=["POST"], endpoint="reset_system_config")
@superadmin_required
def reset_system_config():
    """Delete all user-defined configurations (not ENV values)."""
    SystemConfig.query.delete()
    db.session.commit()
    flash("All system configurations reset to defaults.", "danger")
    return redirect(url_for("superadmin.system_config"))


# ================================
# Route: Add New Config Entry
# ================================
@superadmin_bp.route("/system-config/add", methods=["POST"], endpoint="add_config")
@superadmin_required
def add_config():
    """Add a new config key-value pair to the DB."""
    key = request.form.get("key", "").upper()
    value = request.form.get("value", "")
    if not key or not value:
        flash("Both key and value are required.", "danger")
    else:
        exists = SystemConfig.query.filter_by(key=key).first()
        if exists:
            flash(f"Key '{key}' already exists.", "warning")
        else:
            db.session.add(SystemConfig(key=key, value=value, updated_by=None))
            db.session.commit()
            flash(f"Config '{key}' added successfully.", "success")
    return redirect(url_for("superadmin.system_config"))


# ================================
# Route: Update Existing Config
# ================================
@superadmin_bp.route("/system-config/update/<key>", methods=["POST"], endpoint="update_config")
@superadmin_required
def update_config(key):
    """Update the value of an existing config entry."""
    value = request.form.get("value", "")
    cfg = SystemConfig.query.filter_by(key=key.upper()).first()
    if cfg:
        cfg.value = value
        db.session.commit()
        flash(f"Updated '{key}' to '{value}'.", "success")
    else:
        flash(f"Config key '{key}' not found.", "danger")
    return redirect(url_for("superadmin.system_config"))


# ================================
# Route: Delete Config Entry
# ================================
@superadmin_bp.route("/system-config/delete/<key>", methods=["POST"], endpoint="delete_config")
@superadmin_required
def delete_config(key):
    """Delete a config key from the database."""
    cfg = SystemConfig.query.filter_by(key=key.upper()).first()
    if cfg:
        db.session.delete(cfg)
        db.session.commit()
        flash(f"Config key '{key}' deleted.", "warning")
    else:
        flash(f"Config key '{key}' not found.", "danger")
    return redirect(url_for("superadmin.system_config"))


# ================================
# Route: Export Config to JSON
# ================================
@superadmin_bp.route("/system-config/export", endpoint="export_config")
@superadmin_required
def export_config():
    """
    Export all system configuration entries to a downloadable JSON file.
    """
    configs = SystemConfig.query.order_by(SystemConfig.key).all()
    data = {c.key: c.value for c in configs}
    timestamp = datetime.utcnow().strftime("%Y-%m-%d-%H%M")
    name = f"config_export_{timestamp}.json"
    resp = Response(json.dumps(data, indent=2), mimetype="application/json")
    resp.headers["Content-Disposition"] = f'attachment; filename="{name}"'
    return resp


# ================================
# Route: Regenerate Session Secret
# ================================
@superadmin_bp.route("/system-config/regenerate-session-secret", methods=["POST"], endpoint="regenerate_session_secret")
@superadmin_required
def regenerate_session_secret():
    """
    Generates a new session secret and forces an app restart.
    """
    new_secret = secrets.token_hex(16)
    cfg = SystemConfig.query.filter_by(key=ConfigKeys.SESSION_SECRET).first()
    if not cfg:
        cfg = SystemConfig(key=ConfigKeys.SESSION_SECRET, value=new_secret, updated_by=current_user.id)
        db.session.add(cfg)
    else:
        cfg.value = new_secret
        cfg.updated_at = datetime.utcnow()
    db.session.commit()
    flash("Session secret regenerated; restarting app...", "success")

    # Soft-restart the app using os.execv
    os.execv(sys.executable, [sys.executable] + sys.argv)


# ================================
# Route: Wipe System Monitoring Metrics
# ================================
@superadmin_bp.route("/system-config/wipe-metrics", methods=["POST"], endpoint="wipe_system_metrics")
@superadmin_required
def wipe_metrics():
    """
    Deletes all recorded system metrics from the SystemMonitoring table.
    Useful for resetting charts or freeing space.
    """
    try:
        from .models.system_monitoring import SystemMetric
        deleted = SystemMetric.query.delete()
        db.session.commit()
        flash(f"Wiped {deleted} system metrics.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Error wiping metrics: {e}", "danger")
        logger.error(f"Error wiping metrics: {e}")
    return redirect(url_for("superadmin.system_config"))
