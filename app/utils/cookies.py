import hashlib
import logging
import os
from datetime import datetime, timedelta

from flask import request, current_app, session
from flask_login import current_user
from app.models.session import SessionActivity
from app import db

logger = logging.getLogger(__name__)

def set_session_cookie(user):
    """
    Sets a secure session cookie for the user.
    The cookie contains hashed information about the user's session.
    """
    # Record session in database
    ip_address = request.remote_addr or '0.0.0.0'
    user_agent = request.user_agent.string or 'Unknown'
    
    # Generate unique session ID
    session_id = hashlib.sha256(f"{os.urandom(16)}{user.id}{datetime.utcnow()}".encode()).hexdigest()
    
    # Store in database
    session_activity = SessionActivity(
        user_id=user.id,
        session_id=session_id,
        ip_address=ip_address,
        user_agent=user_agent
    )
    db.session.add(session_activity)
    db.session.commit()
    
    # Store in session cookie
    session['session_id'] = session_id
    session['user_ip'] = ip_address
    session['user_agent'] = user_agent
    
    # Update user's last login information
    user.last_login = datetime.utcnow()
    user.last_ip = ip_address
    user.last_user_agent = user_agent
    db.session.commit()
    
    logger.info(f"Session cookie set for user {user.id} from IP {ip_address}")

def validate_session_cookie(user=None):
    """
    Validates the current user's session cookie.
    Returns True if the session is valid, False otherwise.
    
    Args:
        user: Optional user object to validate against, defaults to current_user
    """
    if not user:
        user = current_user
    
    if not user.is_authenticated:
        return False
    
    # Check if required session data exists
    if 'session_id' not in session or 'user_ip' not in session or 'user_agent' not in session:
        logger.warning(f"Session data missing for user {user.id}")
        return False
    
    # Get current request information
    current_ip = request.remote_addr or '0.0.0.0'
    current_user_agent = request.user_agent.string or 'Unknown'
    
    # Verify the session exists in database
    session_record = SessionActivity.query.filter_by(
        user_id=user.id,
        session_id=session['session_id'],
        is_active=True
    ).first()
    
    if not session_record:
        logger.warning(f"No active session found for user {user.id} with session_id {session['session_id']}")
        return False
    
    # Validate IP address (relaxed for Replit environment)
    if current_ip != session['user_ip']:
        logger.warning(f"IP address changed during session but continuing anyway")
    
    # Validate user agent (relaxed for Replit environment)
    if current_user_agent != session['user_agent']:
        logger.warning("User agent changed during session but continuing anyway")
    
    # Update last activity
    session_record.last_activity = datetime.utcnow()
    db.session.commit()
    
    return True

def clear_session_cookie():
    """Clears the user's session cookie."""
    # Mark session as inactive in database if session_id exists
    if 'session_id' in session:
        session_record = SessionActivity.query.filter_by(
            session_id=session['session_id'],
            is_active=True
        ).first()
        
        if session_record:
            session_record.is_active = False
            db.session.commit()
    
    # Remove session data
    session.pop('session_id', None)
    session.pop('user_ip', None)
    session.pop('user_agent', None)

def generate_csrf_token():
    """Generates a CSRF token for form submission."""
    if '_csrf_token' not in session:
        session['_csrf_token'] = hashlib.sha256(os.urandom(32)).hexdigest()
    return session['_csrf_token']

def validate_csrf_token(token):
    """Validates a CSRF token against the stored session token."""
    stored_token = session.get('_csrf_token')
    if not stored_token or stored_token != token:
        return False
    return True

def get_secure_cookie_config():
    """Returns secure cookie configuration."""
    return {
        'httponly': True,
        'secure': request.is_secure,
        'samesite': 'Lax'
    }