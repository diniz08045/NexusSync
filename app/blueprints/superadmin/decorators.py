from functools import wraps

from flask import abort, flash, redirect, request, url_for
from flask_login import current_user, login_required

from app.extensions import db
from app.blueprints.superadmin.logger import logger


# ----------------------------------------
# Decorator: superadmin_required
# ----------------------------------------
def superadmin_required(f):
    """
    Restricts access to routes requiring superadmin privileges.
    Checks:
    - User is authenticated (via @login_required)
    - User is marked as a superadmin
    - Request originates from an allowed IP address
    """
    @wraps(f)
    @login_required  # Ensures user is logged in before proceeding
    def decorated_function(*args, **kwargs):
        # Optional: Check if the request comes from a whitelisted IP
        if not is_ip_allowed(request.remote_addr):
            logger.warning(
                f"Unauthorized superadmin access from IP: {request.remote_addr}"
            )
            abort(403)  # Forbidden

        # Check if the logged-in user has the is_superadmin flag set
        if not getattr(current_user, "is_superadmin", False):
            logger.warning(f"Unauthorized access attempt: {request.path}")
            flash("You must be logged in as Superadmin to access this page.", "warning")
            return redirect(url_for("superadmin.login"))

        # Log success and proceed with the original view
        logger.info(f"Superadmin access granted for {request.path}")
        return f(*args, **kwargs)

    return decorated_function


# ----------------------------------------
# Function: is_ip_allowed
# ----------------------------------------
def is_ip_allowed(ip_address):
    """
    Checks whether the provided IP address is in the list of allowed IPs.
    Supports both exact match and prefix-based matching (e.g., "10.82.")
    """
    ALLOWED_IPS = [
        "127.0.0.1",     # Localhost IPv4
        "localhost",     # Hostname
        "::1",           # Localhost IPv6
    ]
    for allowed in ALLOWED_IPS:
        # Allow exact match or prefix-based match (if allowed ends with a dot)
        if ip_address == allowed or (
            allowed.endswith(".") and ip_address.startswith(allowed)
        ):
            return True
    return False


# ----------------------------------------
# Function: log_action
# ----------------------------------------
def log_action(action_type, details=""):
    """
    Logs a user action to the database for auditing purposes.
    
    Parameters:
        - action_type: Short label for the type of action (e.g., "LOGIN", "CONFIG_CHANGE")
        - details: Optional longer description of what happened
    """
    from app.blueprints.superadmin.models.audit_logs import AuditLog  # Avoid circular import

    ip_address = request.remote_addr
    user_agent = request.user_agent.string

    new_log = AuditLog(
        user_id=current_user.id if current_user.is_authenticated else None,
        action=action_type,
        details=details,
        ip_address=ip_address,
        user_agent=user_agent,
    )

    try:
        db.session.add(new_log)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error logging action: {str(e)}")

    logger.info(f"Action logged: {action_type} - {details}")
