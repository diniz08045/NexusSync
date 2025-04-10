import logging
import traceback
from flask import render_template
from werkzeug.exceptions import BadRequest, Unauthorized, Forbidden, NotFound, TooManyRequests

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
        logger.warning(f"401 Unauthorized: {error}")
        return render_template('errors/401.html', error=error), 401
    
    @app.errorhandler(403)
    def forbidden_error(error):
        """Handle 403 Forbidden errors."""
        logger.warning(f"403 Forbidden: {error}")
        return render_template('errors/403.html', error=error), 403
    
    @app.errorhandler(404)
    def not_found_error(error):
        """Handle 404 Not Found errors."""
        logger.warning(f"404 Not Found: {error}")
        return render_template('errors/404.html', error=error), 404
    
    @app.errorhandler(429)
    def too_many_requests_error(error):
        """Handle 429 Too Many Requests errors."""
        logger.warning(f"429 Too Many Requests: {error}")
        return render_template('errors/429.html', error=error), 429
    
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