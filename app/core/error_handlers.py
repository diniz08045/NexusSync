import logging

from flask import jsonify, render_template, request
from werkzeug.exceptions import HTTPException

# Set up logger for capturing error details
logger = logging.getLogger(__name__)


def register_error_handlers(app):
    """
    Register custom error handlers to gracefully handle and display
    errors in both JSON and HTML format, depending on the request type.
    """

    # --------------------------
    # 400 - Bad Request
    # --------------------------
    @app.errorhandler(400)
    def bad_request_error(error):
        logger.error(f"400 Bad Request: {error}")
        if request.is_json:
            return jsonify(error=str(error)), 400
        return render_template("error.html", title="Bad Request", error=error), 400

    # --------------------------
    # 401 - Unauthorized
    # --------------------------
    @app.errorhandler(401)
    def unauthorized_error(error):
        logger.error(f"401 Unauthorized: {error}")
        if request.is_json:
            return jsonify(error="Authentication required"), 401
        return render_template("error.html", title="Unauthorized", error="Authentication required"), 401

    # --------------------------
    # 403 - Forbidden
    # --------------------------
    @app.errorhandler(403)
    def forbidden_error(error):
        logger.error(f"403 Forbidden: {error}")
        if request.is_json:
            return jsonify(error="You do not have permission to access this resource"), 403
        return render_template("error.html", title="Forbidden", error="You do not have permission to access this resource"), 403

    # --------------------------
    # 404 - Not Found
    # --------------------------
    @app.errorhandler(404)
    def not_found_error(error):
        logger.error(f"404 Not Found: {error}")
        if request.is_json:
            return jsonify(error="Resource not found"), 404
        return render_template("error.html", title="Not Found", error="The requested resource was not found"), 404

    # --------------------------
    # 429 - Too Many Requests
    # --------------------------
    @app.errorhandler(429)
    def too_many_requests_error(error):
        logger.error(f"429 Too Many Requests: {error}")
        if request.is_json:
            return jsonify(error="Too many requests. Please try again later."), 429
        return render_template("error.html", title="Too Many Requests", error="Too many requests. Please try again later."), 429

    # --------------------------
    # 500 - Internal Server Error
    # --------------------------
    @app.errorhandler(500)
    def internal_server_error(error):
        logger.error(f"500 Internal Server Error: {error}")
        if request.is_json:
            return jsonify(error="An internal server error occurred"), 500
        return render_template("error.html", title="Server Error", error="An internal server error occurred"), 500

    # --------------------------
    # Fallback for All Exceptions
    # --------------------------
    @app.errorhandler(Exception)
    def handle_exception(error):
        """
        Catches any unhandled exceptions, including HTTP and system-level errors.
        Returns a meaningful error response with proper logging.
        """
        logger.exception("Unhandled exception", exc_info=error)

        if isinstance(error, HTTPException):
            # Use the HTTPException's built-in message and code
            return render_template("error.html", title=f"Error {error.code}", error=error.description), error.code

        # Generic fallback for unexpected errors
        if request.is_json:
            return jsonify(error="An unexpected error occurred"), 500
        return render_template("error.html", title="Unexpected Error", error="An unexpected error occurred"), 500
