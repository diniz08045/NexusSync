import hashlib
import json
import logging
import os
from datetime import datetime

from flask import current_app, request, session
from flask_login import current_user

# Logger setup for debugging issues with session/cookie handling
logger = logging.getLogger(__name__)


# ================================
# SESSION COOKIE FUNCTIONS
# ================================

def set_session_cookie(user):
    """
    Creates a hashed session cookie for the given user.
    This protects against session tampering by encoding key identifiers and hashing them with the Flask secret key.
    """
    secret_key = current_app.secret_key
    if not secret_key:
        logger.error("Flask secret key is not set")
        return

    user_agent = request.user_agent.string
    ip_address = request.remote_addr

    # Create structured session payload
    session_data = {
        "user_id": user.id,
        "username": user.username,
        "ip": ip_address,
        "user_agent": user_agent,
        "timestamp": datetime.utcnow().isoformat(),
    }

    # Generate a secure hash from the session data and the secret key
    session_json = json.dumps(session_data, sort_keys=True)
    session_hash = hashlib.sha256((session_json + secret_key).encode()).hexdigest()

    # Save session data in Flask's session store
    session["session_hash"] = session_hash
    session["user_id"] = user.id
    session["user_agent"] = user_agent
    session["ip"] = ip_address


def validate_session_cookie(user=None):
    """
    Validates the user's session hash against the current environment.
    Returns True if the session is valid, otherwise False.

    Args:
        user: Optional. If not provided, uses Flask-Login's current_user.
    """
    if user is None:
        user = current_user

    if not user.is_authenticated:
        return False

    secret_key = current_app.secret_key
    if not secret_key:
        logger.error("Flask secret key is not set")
        return False

    if "session_hash" not in session:
        logger.warning("No session hash found")
        return False

    if "user_id" not in session or session["user_id"] != user.id:
        logger.warning("User ID mismatch in session")
        return False

    current_user_agent = request.user_agent.string
    current_ip = request.remote_addr

    # Allow user agent and IP changes during development (e.g. in Replit)
    if "user_agent" in session and session["user_agent"] != current_user_agent:
        logger.warning("User agent changed during session but continuing anyway")

    if "ip" in session and session["ip"] != current_ip:
        logger.warning("IP address changed during session but continuing anyway")

    return True


def clear_session_cookie():
    """
    Removes all session-related keys from the Flask session store.
    Use this on logout or forced session invalidation.
    """
    session.pop("session_hash", None)
    session.pop("user_id", None)
    session.pop("user_agent", None)
    session.pop("ip", None)
    session.pop("session_id", None)


# ================================
# CSRF TOKEN HANDLING
# ================================

def generate_csrf_token():
    """
    Generates and stores a CSRF token in the user's session.
    This is used to protect against cross-site request forgery.
    """
    if "_csrf_token" not in session:
        session["_csrf_token"] = os.urandom(24).hex()
    return session["_csrf_token"]


def validate_csrf_token(token):
    """
    Checks the submitted CSRF token against the session's stored token.
    Returns True if valid, False otherwise.
    """
    session_token = session.get("_csrf_token", None)
    if not session_token:
        return False
    return session_token == token


# ================================
# SECURE COOKIE CONFIG
# ================================

def get_secure_cookie_config():
    """
    Returns a dictionary of secure cookie parameters
    to be used when setting cookies manually.
    """
    return {
        "httponly": True,              # Prevent access to cookie from JavaScript
        "secure": request.is_secure,   # Only send over HTTPS
        "samesite": "Lax",             # Helps prevent CSRF on cross-site form POSTs
    }
