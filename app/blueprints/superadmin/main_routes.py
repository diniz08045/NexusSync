import os
import secrets
import sys
from datetime import datetime

from flask import (
    Response, flash, redirect, render_template, request,
    url_for, current_app, session, abort
)
from flask_login import login_user, logout_user, current_user
from werkzeug.security import generate_password_hash

from app.extensions import db
from app.blueprints.superadmin.blueprint import superadmin_bp
from app.blueprints.superadmin.decorators import is_ip_allowed, log_action, superadmin_required
from app.blueprints.superadmin.forms import SuperAdminLoginForm, ChangePasswordForm
from app.blueprints.superadmin.logger import logger
from app.blueprints.superadmin.models.system_config import SystemConfig


# Retrieve credentials from environment variables
SUPER_ADMIN_USERNAME = os.environ.get("SUPER_ADMIN_USERNAME", "superadmin")
SUPER_ADMIN_PASSWORD_HASH = os.environ.get("SUPER_ADMIN_PASSWORD_HASH")

# If not set, generate a default hash — for demo/dev use only!
if not SUPER_ADMIN_PASSWORD_HASH:
    SUPER_ADMIN_PASSWORD_HASH = generate_password_hash("change_this_password_immediately!")

# Track login attempts per IP to limit brute-force attempts
login_attempts = {}

def get_development_mode():
    """Returns True if the app is in DEBUG (development) mode."""
    return current_app.config.get("DEBUG", True)


# -------------------------------
# Route: Superadmin Login
# -------------------------------
@superadmin_bp.route("/login", methods=["GET", "POST"])
def login():
    """
    Renders login form and handles superadmin authentication.
    Includes brute-force protection by IP and role validation.
    """
    session["is_superadmin"] = False
    form = SuperAdminLoginForm()

    # Reject requests from unauthorized IPs
    if not is_ip_allowed(request.remote_addr):
        logger.warning(f"Unauthorized superadmin login attempt from IP: {request.remote_addr}")
        abort(403)

    # Handle form submission
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        ip = request.remote_addr

        # Check for brute-force attempt from this IP
        if ip in login_attempts and login_attempts[ip]["count"] >= 5:
            if (datetime.utcnow() - login_attempts[ip]["last_attempt"]).total_seconds() < 3600:
                flash("Too many failed login attempts. Please try again later.", "danger")
                logger.warning(f"Excessive failed superadmin login attempts from IP: {ip}")
                return render_template("superadmin/login.html", form=form)
            else:
                # Reset counter after 1 hour
                login_attempts[ip] = {"count": 0, "last_attempt": datetime.utcnow()}

        from app.models.user import User
        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password) and user.has_role("superadmin"):
            login_user(user)
            log_action("LOGIN", f"Successful superadmin login by {username}")
            session["is_superadmin"] = True
            login_attempts[ip] = {"count": 0, "last_attempt": datetime.utcnow()}
            flash("Logged in successfully as superadmin.", "success")
            return redirect(url_for("superadmin.dashboard"))
        else:
            login_attempts.setdefault(ip, {"count": 0, "last_attempt": datetime.utcnow()})
            login_attempts[ip]["count"] += 1
            login_attempts[ip]["last_attempt"] = datetime.utcnow()
            log_action("FAILED_LOGIN", f"Failed superadmin login with username: {username}")
            flash("Invalid username or password.", "danger")

    return render_template("superadmin/login.html", form=form)


# -------------------------------
# Route: Dev Login (Development Only)
# -------------------------------
@superadmin_bp.route("/dev-login", methods=["GET", "POST"], endpoint="dev_login")
def dev_login():
    """
    Allows bypass login in development mode.
    Use only when DEBUG=True.
    """
    if not current_app.config.get("DEBUG", True):
        abort(403)

    session["is_superadmin"] = True
    flash("Development login successful", "warning")
    return redirect(url_for("superadmin.dashboard"))


# -------------------------------
# Route: Superadmin Dashboard
# -------------------------------
@superadmin_bp.route("/dashboard")
@superadmin_required
def dashboard():
    """Main dashboard view for Superadmin users."""
    return render_template("superadmin/dashboard.html")


# -------------------------------
# Route: Logout
# -------------------------------
@superadmin_bp.route("/logout")
@superadmin_required
def logout():
    """
    Logs out the current superadmin and clears session flags.
    """
    log_action("LOGOUT", "Superadmin logged out")
    logout_user()
    session.pop("is_superadmin", None)
    session.pop("superadmin_username", None)
    flash("You have been logged out.", "info")
    return redirect(url_for("superadmin.login"))


# -------------------------------
# Route: Change Superadmin Password
# -------------------------------
@superadmin_bp.route("/change-password", methods=["GET", "POST"])
@superadmin_required
def change_password():
    """
    Allows superadmin to change their password securely.
    Logs the change and forces re-login after update.
    """
    form = ChangePasswordForm()

    if form.validate_on_submit():
        from app.models.user import User
        user = current_user  # Authenticated via Flask-Login

        if user and user.check_password(form.current_password.data):
            user.set_password(form.new_password.data)
            db.session.commit()

            log_action("CONFIG_CHANGE", f"Superadmin '{user.username}' changed their password.")

            # Log out user and clear session after password change
            session.pop("is_superadmin", None)
            logout_user()

            flash("Password changed. Please log in again.", "info")
            return redirect(url_for("superadmin.login"))
        else:
            flash("Invalid current password.", "danger")

    return render_template("superadmin/change_password.html", form=form)


# -------------------------------
# Route: Force Logout
# -------------------------------
@superadmin_bp.route("/force-logout", methods=["POST"], endpoint="force_logout")
@superadmin_required
def force_logout():
    """
    Logs out the current session. Can be extended to support
    invalidating all sessions in a real-world multi-user setup.
    """
    logout_user()
    log_action("FORCE_LOGOUT", "Force logout triggered by superadmin")
    flash("Force logout executed. Please log in again.", "info")
    return redirect(url_for("superadmin.login"))


# -------------------------------
# Route: Restart Application
# -------------------------------
@superadmin_bp.route("/restart-app", methods=["POST"], endpoint="restart_application")
@superadmin_required
def restart_application():
    """
    Soft restarts the Flask application process.
    Useful for applying changes without full server restart.
    """
    try:
        log_action("RESTART_APP", "Application is restarting.")
        flash("Application is restarting...", "success")

        # Restart the Python process with the same arguments
        os.execv(sys.executable, [sys.executable] + sys.argv)

    except Exception as e:
        current_app.logger.error("Error during restart: %s", str(e), exc_info=True)
        db.session.rollback()
        flash(f"Error restarting application: {str(e)}", "danger")
        return redirect(url_for("superadmin.system_config_view"))
