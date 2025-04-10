"""
Security utilities for the application.
"""
from datetime import datetime, timedelta
from flask import request, current_app
import logging

from app.models.login_attempt import LoginAttempt
from app.models.user import User
from app import db

logger = logging.getLogger(__name__)

def get_client_ip():
    """
    Get the client IP address from the request.
    Handles cases where the application is behind a proxy.
    """
    if request.headers.get('X-Forwarded-For'):
        # If behind a proxy, get the real IP
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    else:
        ip = request.remote_addr
    return ip

def check_login_attempts(user_id, ip_address=None, max_attempts=5, window_minutes=15):
    """
    Check if there have been too many failed login attempts for a user
    or from an IP address.
    
    Args:
        user_id (int): The user ID to check
        ip_address (str, optional): The IP address to check
        max_attempts (int): Maximum number of allowed failed attempts
        window_minutes (int): Time window in minutes to check for attempts
        
    Returns:
        tuple: (is_blocked, remaining_time_seconds)
    """
    time_window = datetime.utcnow() - timedelta(minutes=window_minutes)
    
    # Check failed attempts for this user
    user_attempts = LoginAttempt.query.filter(
        LoginAttempt.user_id == user_id,
        LoginAttempt.successful == False,
        LoginAttempt.timestamp > time_window
    ).count()
    
    # If IP address is provided, also check for attempts from this IP
    ip_attempts = 0
    if ip_address:
        ip_attempts = LoginAttempt.query.filter(
            LoginAttempt.ip_address == ip_address,
            LoginAttempt.successful == False,
            LoginAttempt.timestamp > time_window
        ).count()
    
    # Get the most recent failed attempt to calculate time remaining in block
    most_recent = LoginAttempt.query.filter(
        LoginAttempt.user_id == user_id,
        LoginAttempt.successful == False
    ).order_by(LoginAttempt.timestamp.desc()).first()
    
    remaining_seconds = 0
    if most_recent:
        block_end_time = most_recent.timestamp + timedelta(minutes=window_minutes)
        if datetime.utcnow() < block_end_time:
            remaining_seconds = int((block_end_time - datetime.utcnow()).total_seconds())
    
    # Account is blocked if too many attempts from either user_id or IP
    is_blocked = (user_attempts >= max_attempts) or (ip_attempts >= max_attempts * 2)
    
    if is_blocked:
        logger.warning(f"Login blocked - User ID: {user_id}, IP: {ip_address}, " 
                      f"User attempts: {user_attempts}, IP attempts: {ip_attempts}")
    
    return is_blocked, remaining_seconds

def log_security_event(event_type, user_id=None, details=None):
    """
    Log a security-related event to both the application log and database.
    Optionally creates notifications for suspicious activities.
    
    Args:
        event_type (str): Type of security event (e.g., 'login_failed', 'password_reset')
        user_id (int, optional): User ID associated with the event
        details (dict, optional): Additional details about the event
    """
    if details is None:
        details = {}
        
    ip_address = get_client_ip()
    user_agent = request.user_agent.string if request and request.user_agent else "Unknown"
    
    # Add IP and user agent to details if not already present
    if 'ip' not in details:
        details['ip'] = ip_address
    if 'user_agent' not in details:
        details['user_agent'] = user_agent
    
    # Log to application logs
    log_message = f"Security event: {event_type}, User: {user_id}, IP: {ip_address}"
    if details:
        log_message += f", Details: {details}"
    logger.info(log_message)
    
    # Check if this is a suspicious event that should trigger a notification
    suspicious_events = {
        'login_blocked': {
            'title': 'Account Temporarily Locked',
            'message': 'Your account has been temporarily locked due to too many failed login attempts. For security purposes, please wait a few minutes before trying again.'
        },
        'password_reset_requested': {
            'title': 'Password Reset Requested',
            'message': f'A password reset was requested for your account from IP {ip_address}. If you did not request this, please contact support immediately.'
        },
        'login_failed': {
            'title': 'Failed Login Attempt',
            'message': f'There was a failed login attempt on your account from IP {ip_address}. If this wasn\'t you, please review your account security.'
        },
        'new_location_login': {
            'title': 'Login from New Location',
            'message': f'Your account was accessed from a new location ({ip_address}). If this wasn\'t you, please change your password immediately.'
        }
    }
    
    # If this is a suspicious event and we have a user_id, create a notification
    if user_id and event_type in suspicious_events:
        try:
            from app.models.notification import Notification
            from app import db
            
            notification = Notification(
                user_id=user_id,
                title=suspicious_events[event_type]['title'],
                message=suspicious_events[event_type]['message']
            )
            db.session.add(notification)
            db.session.commit()
            logger.info(f"Created security notification for user_id {user_id}: {event_type}")
            
        except Exception as e:
            logger.error(f"Failed to create security notification: {str(e)}")
            db.session.rollback()
    
    # TODO: In the future, implement a SecurityLog model to store these events