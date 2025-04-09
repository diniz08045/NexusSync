import os
import logging
import json
import hashlib
from datetime import datetime, timedelta
from flask import request, current_app, make_response, session
from flask_login import current_user

logger = logging.getLogger(__name__)

def set_session_cookie(user):
    """
    Sets a secure session cookie for the user.
    The cookie contains hashed information about the user's session.
    """
    secret_key = current_app.secret_key
    if not secret_key:
        logger.error("Flask secret key is not set")
        return
    
    # Create a fingerprint of the user's environment
    user_agent = request.user_agent.string
    ip_address = request.remote_addr
    
    # Create a session hash
    session_data = {
        'user_id': user.id,
        'username': user.username,
        'ip': ip_address,
        'user_agent': user_agent,
        'timestamp': datetime.utcnow().isoformat()
    }
    
    # Create a hash of the session data combined with the secret key
    session_json = json.dumps(session_data, sort_keys=True)
    session_hash = hashlib.sha256((session_json + secret_key).encode()).hexdigest()
    
    # Store the hash in the session
    session['session_hash'] = session_hash
    session['user_id'] = user.id
    session['user_agent'] = user_agent
    session['ip'] = ip_address

def validate_session_cookie():
    """
    Validates the current user's session cookie.
    Returns True if the session is valid, False otherwise.
    """
    if not current_user.is_authenticated:
        return False
    
    secret_key = current_app.secret_key
    if not secret_key:
        logger.error("Flask secret key is not set")
        return False
    
    # Check if session hash exists
    if 'session_hash' not in session:
        logger.warning("No session hash found")
        return False
    
    # Check user ID
    if 'user_id' not in session or session['user_id'] != current_user.id:
        logger.warning("User ID mismatch in session")
        return False
    
    # Check if user agent and IP have changed
    current_user_agent = request.user_agent.string
    current_ip = request.remote_addr
    
    if 'user_agent' in session and session['user_agent'] != current_user_agent:
        logger.warning("User agent changed during session")
        return False
    
    if 'ip' in session and session['ip'] != current_ip:
        logger.warning("IP address changed during session")
        return False
    
    return True

def clear_session_cookie():
    """Clears the user's session cookie."""
    session.pop('session_hash', None)
    session.pop('user_id', None)
    session.pop('user_agent', None)
    session.pop('ip', None)

def generate_csrf_token():
    """Generates a CSRF token for form submission."""
    if '_csrf_token' not in session:
        session['_csrf_token'] = os.urandom(24).hex()
    return session['_csrf_token']

def validate_csrf_token(token):
    """Validates a CSRF token against the stored session token."""
    session_token = session.get('_csrf_token', None)
    if not session_token:
        return False
    return session_token == token

def get_secure_cookie_config():
    """Returns secure cookie configuration."""
    return {
        'httponly': True,
        'secure': request.is_secure,
        'samesite': 'Lax'
    }
