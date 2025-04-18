from datetime import datetime, timedelta

from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user

from app.extensions import db
from .blueprint import superadmin_bp
from app.blueprints.superadmin.decorators import superadmin_required
from app.blueprints.superadmin.forms import StartupConfigForm
from app.blueprints.superadmin.logger import logger

# Import the StartupConfig model
from app.blueprints.superadmin.models.startup_config import StartupConfig


# -------------------------------
# Route: Startup Configuration
# -------------------------------
@superadmin_bp.route(
    "/startup-config", methods=["GET", "POST"], endpoint="startup_config"
)
@superadmin_required
def startup_config_view():
    """
    Render and process the Startup Configuration page.

    This page allows superadmins to control automatic behaviors
    triggered on server startup, like auto-migration or service launch.
    """
    now = datetime.utcnow()
    yesterday = now - timedelta(days=1)  # Used for displaying recent changes if needed
    form = StartupConfigForm()

    # -------------------------------------
    # Handle form submission (POST)
    # -------------------------------------
    if form.validate_on_submit():
        try:
            # Fetch existing config or create new one
            startup = StartupConfig.query.first()
            if not startup:
                # No record found, create new entry
                startup = StartupConfig(
                    auto_migrate=form.auto_migrate.data,
                    auto_create_admin=form.auto_create_admin.data,
                    auto_backup=form.auto_backup.data,
                    auto_start_services=form.auto_start_services.data,
                    startup_timeout=form.startup_timeout.data,
                    updated_by=current_user.id,
                )
                db.session.add(startup)
            else:
                # Update existing config fields
                startup.auto_migrate = form.auto_migrate.data
                startup.auto_create_admin = form.auto_create_admin.data
                startup.auto_backup = form.auto_backup.data
                startup.auto_start_services = form.auto_start_services.data
                startup.startup_timeout = form.startup_timeout.data
                startup.updated_by = current_user.id

            db.session.commit()

            # Log the configuration change
            from app.blueprints.superadmin.decorators import log_action
            log_action("STARTUP_CONFIG_CHANGE", "Startup configuration updated")

            flash("Startup configuration updated successfully.", "success")
            return redirect(url_for("superadmin.startup_config"))

        except Exception as e:
            db.session.rollback()
            flash(f"Error updating startup configuration: {str(e)}", "danger")
            logger.error(f"Error in startup config update: {str(e)}")

    # -------------------------------------
    # Load initial values into form (GET)
    # -------------------------------------
    elif request.method == "GET":
        startup = StartupConfig.query.first()
        if startup:
            # Populate form with saved values
            form.auto_start_services.data = startup.auto_start_services
            form.startup_timeout.data = startup.startup_timeout
            form.auto_migrate.data = startup.auto_migrate
            form.auto_create_admin.data = startup.auto_create_admin
            form.auto_backup.data = startup.auto_backup
        else:
            # Use sensible default values
            form.auto_start_services.data = True
            form.startup_timeout.data = 60

    # Render the form template
    now = datetime.now()
    return render_template(
        "superadmin/startup_config.html",
        form=form,
        now=now,
        yesterday=yesterday,
        datetime=datetime
    )
