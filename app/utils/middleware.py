"""
Middleware module for Flask applications.

This module provides middleware functions to be applied to Flask requests and responses,
including security middleware from the security module.
"""

from functools import wraps
import logging

from flask import Flask, request, session, g, redirect, url_for, current_app, abort
from flask_login import current_user

from app.utils.security import is_safe_url, security_logger

# Setup the middleware logger
middleware_logger = logging.getLogger("app.middleware")
middleware_logger.setLevel(logging.INFO)

def apply_middlewares(app: Flask) -> None:
    """
    Apply all middleware functions to a Flask application.
    
    Args:
        app: The Flask application
    """
    # Track user activity
    @app.before_request
    def track_user_activity() -> None:
        """Track user activity for security monitoring."""
        # Skip for static files
        if request.path.startswith('/static/'):
            return
        
        # Record request details
        g.request_start_time = request.environ.get('REQUEST_TIME', None)
        g.request_path = request.path
        g.request_method = request.method
        g.request_ip = request.remote_addr
        g.request_user_agent = request.headers.get('User-Agent', '')
        g.request_referrer = request.referrer
        
        # Track current user if authenticated
        if current_user.is_authenticated:
            g.user_id = current_user.id
            
            # Check for suspicious activity like IP change
            last_ip = session.get('last_ip')
            if last_ip and last_ip != request.remote_addr:
                security_logger.warning(
                    f"IP change detected for user {current_user.id}: "
                    f"{last_ip} -> {request.remote_addr}"
                )
                
                # Depending on your security policy, you might want to:
                # - Force re-login
                # - Send notification
                # - Block the request
                # session.clear()
                # flash("Your session has been terminated due to security concerns. Please login again.", "warning")
                # return redirect(url_for('auth.login'))
            
            # Update last activity time and IP
            session['last_ip'] = request.remote_addr
            session['last_activity'] = g.request_start_time
    
    # Log response time and status for monitoring
    @app.after_request
    def log_response(response) -> None:
        """Log response details for monitoring and auditing."""
        # Skip for static files
        if request.path.startswith('/static/'):
            return response
            
        # Calculate response time if start time was recorded
        if hasattr(g, 'request_start_time') and g.request_start_time:
            duration = request.environ.get('REQUEST_TIME', 0) - g.request_start_time
            log_data = {
                'path': getattr(g, 'request_path', request.path),
                'method': getattr(g, 'request_method', request.method),
                'status': response.status_code,
                'duration': round(duration * 1000, 2),  # in milliseconds
                'ip': getattr(g, 'request_ip', request.remote_addr),
            }
            
            # Add user info if authenticated
            if hasattr(g, 'user_id'):
                log_data['user_id'] = g.user_id
                
            # Log at different levels based on status code
            if 400 <= response.status_code < 500:
                middleware_logger.warning(f"Client error: {log_data}")
            elif response.status_code >= 500:
                middleware_logger.error(f"Server error: {log_data}")
            else:
                middleware_logger.info(f"Request completed: {log_data}")
                
        return response
    
    # Check session timeout
    @app.before_request
    def check_session_timeout() -> None:
        """Check for session timeout and terminate expired sessions."""
        # Skip for static files and non-authenticated routes
        if request.path.startswith('/static/') or request.path.startswith('/auth/login'):
            return
            
        # If user is authenticated, check last activity time
        if current_user.is_authenticated and 'last_activity' in session:
            last_activity = session.get('last_activity')
            timeout = current_app.config.get('SESSION_TIMEOUT', 3600)  # Default 1 hour
            
            if request.environ.get('REQUEST_TIME', 0) - last_activity > timeout:
                security_logger.info(f"Session timeout for user {current_user.id}")
                session.clear()
                return redirect(url_for('auth.login', next=request.path))
    
    # Apply origin validation for sensitive requests
    @app.before_request
    def validate_origin() -> None:
        """Validate request origin for cross-site request protection."""
        # Skip for safe methods
        if request.method in ('GET', 'HEAD', 'OPTIONS'):
            return
            
        # Check origin for cross-site requests
        origin = request.headers.get('Origin')
        if origin:
            if not is_safe_url(origin):
                security_logger.warning(f"Invalid origin detected: {origin}")
                abort(403)
                
    middleware_logger.info("All middlewares applied successfully")