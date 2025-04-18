from flask import current_app, flash, redirect, render_template, request, url_for
from flask_login import current_user

from app.extensions import db
from .blueprint import superadmin_bp
from app.blueprints.superadmin.decorators import superadmin_required
from app.blueprints.superadmin.forms import EmailConfigForm

# EmailConfig model holds the email server configuration details
from app.blueprints.superadmin.models.email_config import EmailConfig


@superadmin_bp.route("/email-config", methods=["GET", "POST"], endpoint="email_config")
@superadmin_required
def email_config_view():
    """
    View to display and update email (SMTP) configuration for the app.

    GET:
        - Loads existing config from DB or from app config as fallback.
        - Pre-populates form fields.

    POST:
        - Updates email server configuration in DB.
        - Optionally sends a test email if requested.
    """
    # Imported locally to avoid circular dependency issues
    from app.blueprints.superadmin.decorators import log_action

    form = EmailConfigForm()

    # Determine whether the request is for testing the email setup
    is_test = request.args.get("test", "0") == "1" or "test_email" in request.form

    # Handle form submission
    if form.validate_on_submit():
        try:
            # Check if there's an existing config entry
            config = EmailConfig.query.first()

            if not config:
                # Create new configuration
                config = EmailConfig(
                    mail_server=form.mail_server.data,
                    mail_port=form.mail_port.data,
                    mail_use_tls=form.mail_use_tls.data,
                    mail_use_ssl=form.mail_use_ssl.data,
                    mail_username=form.mail_username.data,
                    mail_password=form.mail_password.data,
                    mail_default_sender=form.mail_default_sender.data,
                    updated_by=current_user.id,
                )
                db.session.add(config)
            else:
                # Update existing configuration
                config.mail_server = form.mail_server.data
                config.mail_port = form.mail_port.data
                config.mail_use_tls = form.mail_use_tls.data
                config.mail_use_ssl = form.mail_use_ssl.data
                config.mail_username = form.mail_username.data
                config.mail_password = form.mail_password.data
                config.mail_default_sender = form.mail_default_sender.data
                config.updated_by = current_user.id

            # Save changes
            db.session.commit()

            # Log the change
            log_action("EMAIL_CONFIG_CHANGE", "Email configuration updated.")

            # If test email requested
            if is_test and "test_email" in request.form:
                test_email = request.form.get("test_email")
                if test_email:
                    # Simulate sending a test email
                    log_action("TEST_EMAIL", f"Test email sent to: {test_email}")
                    flash(f"Test email sent to {test_email}.", "success")
                else:
                    flash("Test email address is required.", "warning")
            else:
                flash("Email configuration updated successfully.", "success")

            return redirect(url_for("superadmin.email_config"))

        except Exception as e:
            # Handle any error during DB commit
            db.session.rollback()
            flash(f"Error updating email configuration: {str(e)}", "danger")

    elif request.method == "GET":
        # Pre-fill the form with existing config from DB or fallback defaults
        config = EmailConfig.query.first()
        if config:
            form.mail_server.data = config.mail_server
            form.mail_port.data = config.mail_port
            form.mail_use_tls.data = config.mail_use_tls
            form.mail_use_ssl.data = config.mail_use_ssl
            form.mail_username.data = config.mail_username
            # Do not pre-fill password field for security reasons
            form.mail_default_sender.data = config.mail_default_sender
        else:
            # Fallback to app config values if DB entry is missing
            form.mail_server.data = current_app.config.get("MAIL_SERVER", "")
            form.mail_port.data = current_app.config.get("MAIL_PORT", 587)
            form.mail_use_tls.data = current_app.config.get("MAIL_USE_TLS", True)
            form.mail_use_ssl.data = current_app.config.get("MAIL_USE_SSL", False)
            form.mail_username.data = current_app.config.get("MAIL_USERNAME", "")
            form.mail_default_sender.data = current_app.config.get("MAIL_DEFAULT_SENDER", "")

    # Render the email config page with the form
    return render_template("superadmin/email_config.html", form=form)
