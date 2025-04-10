"""
Flask-SecurityPlus Extension

A comprehensive security extension for Flask applications that bundles
all security features into an easy-to-use Flask extension.
"""

import logging
from typing import Dict, Any, Optional, List, Callable, Union

from flask import Flask, Blueprint, request, current_app, g, Response

from app.utils.security_init import configure_security, security_health_check
from app.utils.security_headers import add_security_headers
from app.utils.token_security import generate_token, verify_token
from app.utils.url_validation import is_url_safe, safe_redirect
from app.utils.xss_protection import sanitize_html, sanitize_text, detect_xss_attacks
from app.utils.sql_protection import is_sql_injection_attempt
from app.utils.file_security import process_uploaded_file
from app.utils.rate_limiting import limit_by_ip, limit_by_user

class SecurityPlus:
    """Flask extension for comprehensive security features."""
    
    def __init__(self, app=None):
        self.logger = logging.getLogger('app.security_plus')
        self.app = None
        
        # Initialize with app if provided
        if app is not None:
            self.init_app(app)
            
    def init_app(self, app: Flask) -> None:
        """
        Initialize the extension with a Flask application.
        
        Args:
            app: The Flask application
        """
        self.app = app
        
        # Register the extension with the application
        app.extensions['security_plus'] = self
        
        # Configure the security features
        config = app.config.get('SECURITY_PLUS', {})
        configure_security(app, config)
        
        # Register a blueprint for security endpoints if enabled
        if config.get('ENABLE_SECURITY_ENDPOINTS', False):
            self._register_blueprint(app)
            
        self.logger.info("SecurityPlus extension initialized")
        
    def _register_blueprint(self, app: Flask) -> None:
        """
        Register a blueprint for security-related endpoints.
        
        Args:
            app: The Flask application
        """
        bp = Blueprint('security', __name__, url_prefix='/security')
        
        @bp.route('/health-check')
        def health_check():
            """Health check endpoint for the security system."""
            if not app.config.get('SECURITY_PLUS', {}).get('EXPOSE_HEALTH_CHECK', False):
                return {'status': 'forbidden'}, 403
                
            return security_health_check(app)
            
        @bp.route('/report-violation', methods=['POST'])
        def report_violation():
            """Endpoint for CSP violation reports."""
            report = request.get_json()
            self.logger.warning(f"CSP Violation: {report}")
            return {'status': 'received'}, 204
            
        app.register_blueprint(bp)
        
    # Helper methods to expose security functionality
    
    def sanitize_html(self, html: str, strict: bool = True) -> str:
        """
        Sanitize HTML to prevent XSS attacks.
        
        Args:
            html: HTML content to sanitize
            strict: Whether to use strict sanitization
            
        Returns:
            str: Sanitized HTML
        """
        return sanitize_html(html, strict)
        
    def sanitize_text(self, text: str) -> str:
        """
        Sanitize text by removing HTML tags.
        
        Args:
            text: Text to sanitize
            
        Returns:
            str: Sanitized text
        """
        return sanitize_text(text)
        
    def is_safe_url(self, url: str) -> bool:
        """
        Check if a URL is safe based on configured policies.
        
        Args:
            url: URL to check
            
        Returns:
            bool: True if URL is safe, False otherwise
        """
        return is_url_safe(url)
        
    def safe_redirect(self, url: str, default_url: str = '/') -> Response:
        """
        Perform a safe redirect after validating the URL.
        
        Args:
            url: URL to redirect to
            default_url: Default URL if the provided URL is unsafe
            
        Returns:
            Response: Redirect response
        """
        return safe_redirect(url, default_url)
        
    def generate_token(self, data: Dict[str, Any], token_type: str = 'default', expiration: int = 3600) -> str:
        """
        Generate a secure, signed token with data.
        
        Args:
            data: Data to include in the token
            token_type: Type of token
            expiration: Token expiration time in seconds
            
        Returns:
            str: Signed token
        """
        return generate_token(data, token_type)
        
    def verify_token(self, token: str, token_type: str = None, max_age: int = None) -> Optional[Dict[str, Any]]:
        """
        Verify a token and return its data if valid.
        
        Args:
            token: Token to verify
            token_type: Expected token type
            max_age: Maximum age of the token in seconds
            
        Returns:
            Optional[Dict[str, Any]]: Token data if valid, None otherwise
        """
        return verify_token(token, token_type, max_age)
        
    def process_uploaded_file(
        self, 
        file, 
        upload_dir: str,
        max_file_size: int = None
    ) -> Optional[Dict[str, str]]:
        """
        Process and securely save an uploaded file.
        
        Args:
            file: The uploaded file
            upload_dir: Directory to save the file in
            max_file_size: Maximum allowed file size in bytes
            
        Returns:
            Optional[Dict[str, str]]: File details if saved successfully, None otherwise
        """
        if max_file_size is None:
            max_file_size = current_app.config.get('MAX_CONTENT_LENGTH', 10 * 1024 * 1024)
            
        return process_uploaded_file(file, upload_dir, max_file_size)
        
    def detect_attack(self, data: Any) -> Dict[str, bool]:
        """
        Detect potential attacks in data.
        
        Args:
            data: Data to analyze
            
        Returns:
            Dict[str, bool]: Attack detection results
        """
        results = {}
        
        # Check for XSS attacks
        results['xss'] = detect_xss_attacks(data)
        
        # Check for SQL injection
        if isinstance(data, str):
            results['sql_injection'] = is_sql_injection_attempt(data)
        elif isinstance(data, dict):
            results['sql_injection'] = any(
                isinstance(v, str) and is_sql_injection_attempt(v)
                for v in data.values()
            )
        else:
            results['sql_injection'] = False
            
        # Check for suspicious URL
        if isinstance(data, str) and (data.startswith('http:') or data.startswith('https:')):
            results['unsafe_url'] = not is_url_safe(data)
        else:
            results['unsafe_url'] = False
            
        return results
        
    # Decorators for routes
    
    def xss_protect(self) -> Callable:
        """
        Decorator to protect a route from XSS attacks.
        
        Returns:
            Callable: Decorated function
        """
        from app.utils.xss_protection import xss_protect as xss_protect_decorator
        return xss_protect_decorator
        
    def limit_by_ip(self, limits: Union[str, List[str]]) -> Callable:
        """
        Decorator to apply rate limits based on IP address.
        
        Args:
            limits: Rate limit string(s)
            
        Returns:
            Callable: Decorated function
        """
        return limit_by_ip(limits)
        
    def limit_by_user(self, limits: Union[str, List[str]]) -> Callable:
        """
        Decorator to apply rate limits based on user ID.
        
        Args:
            limits: Rate limit string(s)
            
        Returns:
            Callable: Decorated function
        """
        return limit_by_user(limits)
        
    def security_headers(self) -> Callable:
        """
        Decorator to add security headers to a response.
        
        Returns:
            Callable: Decorated function
        """
        from functools import wraps
        
        def decorator(f):
            @wraps(f)
            def decorated_function(*args, **kwargs):
                response = f(*args, **kwargs)
                return add_security_headers(response)
            return decorated_function
        return decorator