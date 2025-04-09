import logging
from flask import render_template, request, jsonify
from werkzeug.exceptions import HTTPException

logger = logging.getLogger(__name__)

def register_error_handlers(app):
    """Register error handlers with the Flask application."""
    
    @app.errorhandler(400)
    def bad_request_error(error):
        logger.error(f"400 Bad Request: {error}")
        if request.is_json:
            return jsonify(error=str(error)), 400
        return render_template('error.html', title='Bad Request', error=error), 400
    
    @app.errorhandler(401)
    def unauthorized_error(error):
        logger.error(f"401 Unauthorized: {error}")
        if request.is_json:
            return jsonify(error='Authentication required'), 401
        return render_template('error.html', title='Unauthorized', error='Authentication required'), 401
    
    @app.errorhandler(403)
    def forbidden_error(error):
        logger.error(f"403 Forbidden: {error}")
        if request.is_json:
            return jsonify(error='You do not have permission to access this resource'), 403
        return render_template('error.html', title='Forbidden', error='You do not have permission to access this resource'), 403
    
    @app.errorhandler(404)
    def not_found_error(error):
        logger.error(f"404 Not Found: {error}")
        if request.is_json:
            return jsonify(error='Resource not found'), 404
        return render_template('error.html', title='Not Found', error='The requested resource was not found'), 404
    
    @app.errorhandler(429)
    def too_many_requests_error(error):
        logger.error(f"429 Too Many Requests: {error}")
        if request.is_json:
            return jsonify(error='Too many requests. Please try again later.'), 429
        return render_template('error.html', title='Too Many Requests', error='Too many requests. Please try again later.'), 429
    
    @app.errorhandler(500)
    def internal_server_error(error):
        logger.error(f"500 Internal Server Error: {error}")
        if request.is_json:
            return jsonify(error='An internal server error occurred'), 500
        return render_template('error.html', title='Server Error', error='An internal server error occurred'), 500
    
    @app.errorhandler(Exception)
    def handle_exception(error):
        logger.exception("Unhandled exception", exc_info=error)
        
        # If HTTPException, use its error code and description
        if isinstance(error, HTTPException):
            return render_template('error.html', title=f'Error {error.code}', error=error.description), error.code
        
        # For other exceptions, return a generic 500 error
        if request.is_json:
            return jsonify(error='An unexpected error occurred'), 500
        return render_template('error.html', title='Unexpected Error', error='An unexpected error occurred'), 500
