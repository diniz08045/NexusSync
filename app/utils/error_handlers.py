import logging
import traceback
from datetime import datetime
from flask import render_template, request, current_app
from werkzeug.exceptions import BadRequest, Unauthorized, Forbidden, NotFound, TooManyRequests

from app.utils.security import get_client_ip, log_security_event

logger = logging.getLogger(__name__)

def register_error_handlers(app):
    """Register error handlers with the Flask application."""
    
    @app.errorhandler(400)
    def bad_request_error(error):
        """Handle 400 Bad Request errors."""
        logger.warning(f"400 Bad Request: {error}")
        return render_template('errors/400.html', error=error), 400
    
    @app.errorhandler(401)
    def unauthorized_error(error):
        """Handle 401 Unauthorized errors."""
        ip_address = get_client_ip()
        user_agent = request.user_agent.string if request and request.user_agent else "Unknown"
        path = request.path if request else "Unknown"
        
        # Log more detailed info for security analysis
        logger.warning(f"401 Unauthorized: {error} - IP: {ip_address}, Path: {path}, UA: {user_agent}")
        
        # Track as security event
        details = {
            'path': path,
            'error': str(error)
        }
        log_security_event('unauthorized_access', details=details)
        
        return render_template('errors/401.html', error=error), 401
    
    @app.errorhandler(403)
    def forbidden_error(error):
        """Handle 403 Forbidden errors."""
        ip_address = get_client_ip()
        user_agent = request.user_agent.string if request and request.user_agent else "Unknown"
        path = request.path if request else "Unknown"
        
        # Log more detailed info for security analysis
        logger.warning(f"403 Forbidden: {error} - IP: {ip_address}, Path: {path}, UA: {user_agent}")
        
        # Track as security event
        details = {
            'path': path,
            'error': str(error)
        }
        log_security_event('forbidden_access', details=details)
        
        return render_template('errors/403.html', error=error), 403
    
    @app.errorhandler(404)
    def not_found_error(error):
        """Handle 404 Not Found errors."""
        logger.warning(f"404 Not Found: {error}")
        return render_template('errors/404.html', error=error), 404
    
    @app.errorhandler(429)
    def too_many_requests_error(error):
        """Handle 429 Too Many Requests errors."""
        ip_address = get_client_ip()
        user_agent = request.user_agent.string if request and request.user_agent else "Unknown"
        path = request.path if request else "Unknown"
        
        # Log more detailed info for security analysis
        logger.warning(f"429 Too Many Requests: {error} - IP: {ip_address}, Path: {path}, UA: {user_agent}")
        
        # Track as security event which might indicate a brute force attack
        details = {
            'path': path,
            'error': str(error),
            'endpoint': request.endpoint if request else "Unknown"
        }
        log_security_event('rate_limit_exceeded', details=details)
        
        # Return with Retry-After header to indicate when client can retry
        response = render_template('errors/429.html', error=error), 429
        response[0].headers['Retry-After'] = '60'  # Suggest client wait 60 seconds
        return response
    
    @app.errorhandler(500)
    def internal_server_error(error):
        """Handle 500 Internal Server Error errors."""
        logger.error(f"500 Internal Server Error: {error}")
        traceback.print_exc()
        return render_template('errors/500.html', error=error), 500
    
    @app.errorhandler(Exception)
    def handle_exception(error):
        """Handle unhandled exceptions."""
        # Log the error and traceback
        logger.error(f"Unhandled exception: {error}")
        traceback.print_exc()
        
        # Map specific exceptions to appropriate HTTP status codes
        if isinstance(error, BadRequest):
            return bad_request_error(error)
        elif isinstance(error, Unauthorized):
            return unauthorized_error(error)
        elif isinstance(error, Forbidden):
            return forbidden_error(error)
        elif isinstance(error, NotFound):
            return not_found_error(error)
        elif isinstance(error, TooManyRequests):
            return too_many_requests_error(error)
        
        # Default to 500 error
        return internal_server_error(error)