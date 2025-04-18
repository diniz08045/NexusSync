from datetime import datetime

# Flask utilities for request/response handling and rendering templates
from flask import flash, redirect, render_template, request, url_for
from flask_login import current_user

# Database instance
from app.extensions import db

# Blueprint registration for superadmin routes
from .blueprint import superadmin_bp

# Decorators to restrict access to superadmins and log actions
from app.blueprints.superadmin.decorators import superadmin_required, log_action

# Form class for data retention settings
from app.blueprints.superadmin.forms import DataRetentionForm

# Logger instance for error reporting
from app.blueprints.superadmin.logger import logger

# Model representing the data retention configuration table
from app.blueprints.superadmin.models.data_retention import DataRetention


@superadmin_bp.route(
    "/data-retention", methods=["GET", "POST"], endpoint="data_retention"
)
@superadmin_required
def data_retention_view():
    """
    Handles GET and POST requests to configure data retention policies.
    Accessible only by superadmins.
    
    On GET:
        - Loads current settings from the database (or assigns default values if none exist).
        - Pre-populates the form with existing values.
    
    On POST:
        - Validates form input and either updates or creates a new entry in the database.
        - Commits changes and shows a success message, or handles and logs any errors.
    """
    form = DataRetentionForm()

    # If the form is submitted and passes validation checks
    if form.validate_on_submit():
        try:
            # Attempt to fetch the first existing data retention record
            retention = DataRetention.query.first()

            if not retention:
                # No existing record found; create a new one
                retention = DataRetention(
                    log_retention_days=form.log_retention_days.data,
                    backup_retention_days=form.backup_retention_days.data,
                    user_data_retention_days=form.user_data_retention_days.data,
                    updated_by=current_user.id,
                )
                db.session.add(retention)
            else:
                # Update the existing record with new values from the form
                retention.log_retention_days = form.log_retention_days.data
                retention.backup_retention_days = form.backup_retention_days.data
                retention.user_data_retention_days = form.user_data_retention_days.data
                retention.updated_by = current_user.id

            # Save changes to the database
            db.session.commit()

            # Log the action (this import stays here to avoid circular dependency)
            log_action("RETENTION_CONFIG_CHANGE", "Data retention settings updated")

            # Show a success message to the user
            flash("Data retention settings updated successfully.", "success")

            # Redirect to the same page to avoid re-submission on refresh
            return redirect(url_for("superadmin.data_retention"))

        except Exception as e:
            # Roll back the transaction if an error occurred
            db.session.rollback()

            # Show an error message and log it
            flash(f"Error updating data retention settings: {str(e)}", "danger")
            logger.error(f"Error in data retention update: {str(e)}")

    elif request.method == "GET":
        # On GET request, load current values into the form for display
        retention = DataRetention.query.first()

        if retention:
            # Populate the form with existing values
            form.log_retention_days.data = retention.log_retention_days
            form.backup_retention_days.data = retention.backup_retention_days
            form.user_data_retention_days.data = retention.user_data_retention_days
        else:
            # If no settings exist yet, provide sensible default values
            form.log_retention_days.data = 90
            form.backup_retention_days.data = 180
            form.user_data_retention_days.data = 365

    # Pass the current time to the template for display
    now = datetime.now()

    # Render the HTML template with the form and current time
    return render_template(
        "superadmin/data_retention.html", form=form, now=now, datetime=datetime
    )
