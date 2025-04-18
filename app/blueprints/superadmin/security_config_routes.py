import json
from datetime import datetime

from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user

from app.extensions import db
from .blueprint import superadmin_bp
from app.blueprints.superadmin.decorators import superadmin_required
from app.blueprints.superadmin.forms import SecurityConfigForm
from app.blueprints.superadmin.logger import logger
from app.blueprints.superadmin.models.security_config import SecurityConfig


# -------------------------------
# Route: Security Configuration
# -------------------------------
@superadmin_bp.route(
    "/security-config", methods=["GET", "POST"], endpoint="security_config"
)
@superadmin_required
def security_config_view():
    """
    Renders and processes the Security Configuration page.
    
    Allows superadmins to toggle SSL, WAF, proxy, and CORS settings.
    Stores settings in the database and logs changes in the audit log.
    """
    # Imported locally to avoid circular dependency issues
    from app.blueprints.superadmin.decorators import log_action

    form = SecurityConfigForm()

    # -------------------------------------
    # Handle form submission (POST)
    # -------------------------------------
    if form.validate_on_submit():
        try:
            # Fetch existing config or create new one
            sec_config = SecurityConfig.query.first()
            if not sec_config:
                sec_config = SecurityConfig(
                    ssl_enabled=form.ssl_enabled.data,
                    proxy_enabled=form.proxy_enabled.data,
                    proxy_server=form.proxy_server.data,
                    proxy_port=form.proxy_port.data,
                    waf_enabled=form.waf_enabled.data,
                    cors_enabled=form.cors_enabled.data,
                    cors_allowed_origins=form.cors_allowed_origins.data,
                    updated_by=current_user.id,
                )
                db.session.add(sec_config)
            else:
                # Update the existing config with new form data
                sec_config.ssl_enabled = form.ssl_enabled.data
                sec_config.proxy_enabled = form.proxy_enabled.data
                sec_config.proxy_server = form.proxy_server.data
                sec_config.proxy_port = form.proxy_port.data
                sec_config.waf_enabled = form.waf_enabled.data
                sec_config.cors_enabled = form.cors_enabled.data
                sec_config.cors_allowed_origins = form.cors_allowed_origins.data
                sec_config.updated_by = current_user.id

            db.session.commit()

            # Log configuration changes for auditing
            config_changes = {
                "ssl_enabled": form.ssl_enabled.data,
                "proxy_enabled": form.proxy_enabled.data,
                "proxy_server": form.proxy_server.data,
                "proxy_port": form.proxy_port.data,
                "waf_enabled": form.waf_enabled.data,
                "cors_enabled": form.cors_enabled.data,
                "cors_allowed_origins": form.cors_allowed_origins.data,
            }

            log_action(
                "SECURITY_CONFIG_CHANGE",
                f"Security configuration changed: {json.dumps(config_changes)}",
            )

            flash("Security configuration updated successfully.", "success")
            return redirect(url_for("superadmin.security_config"))

        except Exception as e:
            db.session.rollback()
            flash(f"Error updating security configuration: {str(e)}", "danger")
            logger.error(f"Error in security config update: {str(e)}")

    # -------------------------------------
    # Handle initial form display (GET)
    # -------------------------------------
    elif request.method == "GET":
        sec_config = SecurityConfig.query.first()

        if sec_config:
            # Populate form fields from existing DB config
            form.ssl_enabled.data = sec_config.ssl_enabled
            form.proxy_enabled.data = sec_config.proxy_enabled
            form.proxy_server.data = sec_config.proxy_server
            form.proxy_port.data = sec_config.proxy_port
            form.waf_enabled.data = sec_config.waf_enabled
            form.cors_enabled.data = sec_config.cors_enabled
            form.cors_allowed_origins.data = sec_config.cors_allowed_origins
        else:
            # Set sensible defaults for new installations
            form.ssl_enabled.data = True
            form.proxy_enabled.data = False
            form.waf_enabled.data = True
            form.cors_enabled.data = True
            form.cors_allowed_origins.data = "*"

    # -------------------------------------
    # Render the page
    # -------------------------------------
    now = datetime.now()
    return render_template(
        "superadmin/security_config.html",
        form=form,
        now=now,
        datetime=datetime,
    )
