"""
Location utilities for security purposes.
"""

from datetime import datetime, timedelta

from app.core.security import log_security_event


def check_new_location(user, ip_address):
    """
    Check if this is a login from a new location for the user.
    If it is, log a security event and return True.

    Args:
        user: The user object
        ip_address: The current IP address

    Returns:
        bool: True if this is a new location, False otherwise
    """
    # Skip check if no IP address or no user
    if not ip_address or not user:
        return False

    # Skip check if this is the user's first login
    if not user.last_login:
        return False

    # Check if this IP matches the last login IP
    if user.last_ip == ip_address:
        return False

    # Check recent login attempts from this IP (last 30 days)
    from app.models.login_attempt import LoginAttempt

    time_window = datetime.utcnow() - timedelta(days=30)
    previous_login = LoginAttempt.query.filter(
        LoginAttempt.user_id == user.id,
        LoginAttempt.ip_address == ip_address,
        LoginAttempt.successful == True,
        LoginAttempt.timestamp > time_window,
    ).first()

    # If no previous successful login from this IP in the last 30 days
    if not previous_login:
        # Log security event
        log_security_event(
            "new_location_login",
            user_id=user.id,
            details={"ip": ip_address, "previous_ip": user.last_ip},
        )
        return True

    return False


def check_new_device(user, user_agent):
    """
    Check if this is a login from a new device for the user.
    If it is, log a security event and return True.

    Args:
        user: The user object
        user_agent: The current user agent string

    Returns:
        bool: True if this is a new device, False otherwise
    """
    # Skip check if no user agent or no user
    if not user_agent or not user:
        return False

    # Skip check if this is the user's first login
    if not user.last_login:
        return False

    # Check if this user agent matches the last login user agent
    if user.last_user_agent == user_agent:
        return False

    # Check recent login attempts from this user agent (last 30 days)
    from app.models.login_attempt import LoginAttempt

    time_window = datetime.utcnow() - timedelta(days=30)
    previous_login = LoginAttempt.query.filter(
        LoginAttempt.user_id == user.id,
        LoginAttempt.user_agent == user_agent,
        LoginAttempt.successful == True,
        LoginAttempt.timestamp > time_window,
    ).first()

    # If no previous successful login with this user agent in the last 30 days
    if not previous_login:
        # Log security event
        log_security_event(
            "new_device_login",
            user_id=user.id,
            details={
                "user_agent": user_agent,
                "previous_user_agent": user.last_user_agent,
            },
        )
        return True

    return False
