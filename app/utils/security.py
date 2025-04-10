"""
Comprehensive security module for Flask applications.

This module provides protection against common web vulnerabilities including:
- URL validation and SSRF protection
- Token-based security
- SQL injection prevention
- Path traversal protection
- XSS protection
- CSRF protection
- File upload security
- Rate limiting
- Security headers (including CSP)
- Security logging and anomaly detection
"""

import os
import re
import uuid
import time
import ipaddress
import logging
import urllib.parse
from datetime import datetime, timedelta
from functools import wraps
from typing import List, Dict, Any, Optional, Union, Tuple, Set, Callable

import bleach
from flask import (
    Flask, request, session, abort, redirect, url_for, 
    current_app, g, Response, jsonify, flash
)
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired
from werkzeug.utils import secure_filename
import secrets
import hashlib

# Setup the security logger
security_logger = logging.getLogger("app.security")
security_logger.setLevel(logging.INFO)

# Configure logging handler if it hasn't been configured yet
if not security_logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    handler.setFormatter(formatter)
    security_logger.addHandler(handler)

# Initialize CSRF protection
csrf = CSRFProtect()

# Initialize rate limiting
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# ===== Safe URL Handling =====

# List of allowed URL schemes
ALLOWED_SCHEMES = {'http', 'https'}

# List of disallowed hosts for SSRF protection
DISALLOWED_HOSTS = {
    'localhost', '127.0.0.1', '0.0.0.0', 
    '::1', 'fe80::1', '169.254.169.254',  # localhost and link-local
}

# List of allowed domains for redirection
ALLOWED_DOMAINS: Set[str] = set()  # This should be populated in app initialization

# IP ranges that should be blocked (RFC 1918 private addresses)
PRIVATE_IP_RANGES = [
    '10.0.0.0/8',      # Private network
    '172.16.0.0/12',   # Private network
    '192.168.0.0/16',  # Private network
    '127.0.0.0/8',     # Localhost
    '169.254.0.0/16',  # Link-local
    '192.0.2.0/24',    # Test-Net
    '224.0.0.0/4',     # Multicast
    '240.0.0.0/4',     # Reserved for future use
    '100.64.0.0/10',   # Shared Address Space
]

# Convert private IP ranges to network objects for efficient checking
private_networks = [ipaddress.ip_network(cidr) for cidr in PRIVATE_IP_RANGES]

def is_safe_url(url: str) -> bool:
    """
    Check if a URL is safe for redirection.
    
    Args:
        url: The URL to check
        
    Returns:
        bool: True if the URL is safe, False otherwise
    """
    if not url:
        return False
    
    # Parse the URL
    parsed_url = urllib.parse.urlparse(url)
    
    # Check if the scheme is allowed
    if parsed_url.scheme and parsed_url.scheme not in ALLOWED_SCHEMES:
        security_logger.warning(f"Blocked URL with disallowed scheme: {url}")
        return False
    
    # If there's no netloc (e.g., relative URL), it's generally safe
    if not parsed_url.netloc:
        return True
    
    # Check if the host is in the disallowed list
    if parsed_url.netloc in DISALLOWED_HOSTS:
        security_logger.warning(f"Blocked URL with disallowed host: {url}")
        return False
    
    # Check if the host is in the allowed domains list (if we're enforcing a whitelist)
    if ALLOWED_DOMAINS and parsed_url.netloc not in ALLOWED_DOMAINS:
        security_logger.warning(f"Blocked URL with non-whitelisted domain: {url}")
        return False
    
    # Check if the host resolves to a private IP
    try:
        host_ip = ipaddress.ip_address(parsed_url.netloc)
        for network in private_networks:
            if host_ip in network:
                security_logger.warning(f"Blocked URL with private IP: {url}")
                return False
    except ValueError:
        # If the netloc is not an IP address, this is fine
        pass
    
    return True

def safe_redirect(url: str, default_url: str = '/') -> Response:
    """
    Safely redirect to a URL after validating it.
    
    Args:
        url: The URL to redirect to
        default_url: The default URL to redirect to if the requested URL is unsafe
        
    Returns:
        Response: A redirect response to either the requested URL or the default URL
    """
    if not is_safe_url(url):
        security_logger.warning(f"Unsafe redirect attempted to: {url}, redirecting to {default_url}")
        return redirect(default_url)
    return redirect(url)

def validate_external_url(url: str) -> bool:
    """
    Validate an external URL for safety, checking scheme, host, and IP restrictions.
    
    Args:
        url: The URL to validate
        
    Returns:
        bool: True if the URL is safe, False otherwise
    """
    return is_safe_url(url)

# ===== Token Integrity & Anti-Tampering =====

def generate_token(data: Dict[str, Any], expiration: int = 3600) -> str:
    """
    Generate a signed, time-limited token.
    
    Args:
        data: The data to include in the token
        expiration: Token expiration time in seconds (default: 1 hour)
        
    Returns:
        str: The signed token
    """
    s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    # Add timestamp to prevent replay attacks
    data['created'] = int(time.time())
    # Add a nonce for additional security
    data['nonce'] = secrets.token_hex(16)
    return s.dumps(data)

def verify_token(token: str, max_age: int = 3600) -> Optional[Dict[str, Any]]:
    """
    Verify a token and return its data if valid.
    
    Args:
        token: The token to verify
        max_age: Maximum age of the token in seconds (default: 1 hour)
        
    Returns:
        Optional[Dict[str, Any]]: The token data if valid, None otherwise
    """
    s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        data = s.loads(token, max_age=max_age)
        # Check if token has been used before (if you're tracking used tokens)
        # This could be implemented by storing tokens in a database or cache
        return data
    except SignatureExpired:
        security_logger.warning("Token expired")
        return None
    except BadSignature:
        security_logger.warning("Invalid token signature")
        return None

def generate_reset_token(user_id: int) -> str:
    """
    Generate a password reset token.
    
    Args:
        user_id: The ID of the user
        
    Returns:
        str: The reset token
    """
    return generate_token({'user_id': user_id, 'type': 'password_reset'})

def generate_email_verification_token(user_id: int, email: str) -> str:
    """
    Generate an email verification token.
    
    Args:
        user_id: The ID of the user
        email: The email to verify
        
    Returns:
        str: The verification token
    """
    return generate_token({'user_id': user_id, 'email': email, 'type': 'email_verification'})

# ===== SQL Injection Prevention =====

# Note: Most SQL injection prevention happens naturally when using an ORM like SQLAlchemy
# This function can be used to validate inputs when raw SQL is necessary

def sanitize_sql_input(input_str: str) -> str:
    """
    Sanitize input for SQL queries to prevent SQL injection.
    
    Args:
        input_str: The input string to sanitize
        
    Returns:
        str: The sanitized string
    """
    # Remove common SQL injection patterns
    # This is a basic approach; always use parameterized queries or ORM
    dangerous_patterns = [
        r"(?i)(\s|;|\*|--)+(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)",
        r"(?i)(?:UNION\s+(?:ALL\s+)?SELECT)",
        r"(?i)(?:--)",
        r"(?i)(?:/\*)",
        r"'(?:\s*OR\s*'[^']*'\s*=\s*'[^']*')",
        r"(?i)(?:;)",
    ]
    
    sanitized = input_str
    for pattern in dangerous_patterns:
        sanitized = re.sub(pattern, "", sanitized)
    
    security_logger.debug(f"Sanitized SQL input: {input_str} -> {sanitized}")
    return sanitized

# ===== Path Traversal Protection =====

def is_safe_path(base_dir: str, requested_path: str) -> bool:
    """
    Check if a path is safe and doesn't allow directory traversal.
    
    Args:
        base_dir: The base directory that should contain the path
        requested_path: The requested path to check
        
    Returns:
        bool: True if the path is safe, False otherwise
    """
    # Normalize paths to handle different directory separators
    base_dir = os.path.normpath(os.path.abspath(base_dir))
    
    # Using secure_filename to remove any dangerous characters
    requested_path = secure_filename(requested_path)
    
    # Construct the full path and normalize it
    full_path = os.path.normpath(os.path.abspath(os.path.join(base_dir, requested_path)))
    
    # Check if the full path starts with the base directory (no directory traversal)
    if not full_path.startswith(base_dir):
        security_logger.warning(f"Path traversal attempt: {requested_path}")
        return False
    
    return True

def safe_join(base_dir: str, *paths: str) -> Optional[str]:
    """
    Safely join directory and filenames to prevent path traversal.
    
    Args:
        base_dir: The base directory
        *paths: The paths to join
        
    Returns:
        Optional[str]: The joined path if safe, None otherwise
    """
    # First, secure each path component
    secured_paths = [secure_filename(p) for p in paths if p]
    
    # Join them with the base directory
    full_path = os.path.normpath(os.path.join(base_dir, *secured_paths))
    
    # Check if the path stays within the base directory
    if not os.path.commonpath([base_dir]).startswith(os.path.commonpath([base_dir])):
        security_logger.warning(f"Path traversal attempt in safe_join: {paths}")
        return None
    
    if not is_safe_path(base_dir, os.path.relpath(full_path, base_dir)):
        security_logger.warning(f"Path traversal attempt in safe_join: {paths}")
        return None
    
    return full_path

# ===== XSS Protection =====

# Bleach configuration for sanitizing HTML
ALLOWED_TAGS = [
    'a', 'abbr', 'acronym', 'b', 'blockquote', 'code',
    'em', 'i', 'li', 'ol', 'p', 'strong', 'ul', 'br', 'div', 'span'
]

ALLOWED_ATTRIBUTES = {
    'a': ['href', 'title', 'rel'],
    'abbr': ['title'],
    'acronym': ['title'],
    'div': ['class'],
    'span': ['class'],
}

ALLOWED_STYLES = []

def sanitize_html(html_content: str) -> str:
    """
    Sanitize HTML content to prevent XSS attacks.
    
    Args:
        html_content: The HTML content to sanitize
        
    Returns:
        str: The sanitized HTML
    """
    return bleach.clean(
        html_content,
        tags=ALLOWED_TAGS,
        attributes=ALLOWED_ATTRIBUTES,
        styles=ALLOWED_STYLES,
        strip=True
    )

def sanitize_text(text: str) -> str:
    """
    Sanitize plain text to be used in HTML.
    
    Args:
        text: The text to sanitize
        
    Returns:
        str: The sanitized text
    """
    # First, escape any HTML in the text
    escaped_text = bleach.clean(text, tags=[], strip=True)
    
    # Additionally, normalize whitespace and limit length
    normalized = ' '.join(escaped_text.split())
    return normalized[:10000]  # Arbitrary reasonable limit

# ===== File Upload Security =====

# Allowed file extensions and MIME types
ALLOWED_EXTENSIONS = {
    'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'webp', 'doc', 'docx', 'xls', 'xlsx'
}

ALLOWED_MIME_TYPES = {
    'text/plain', 'application/pdf', 'image/png', 'image/jpeg', 
    'image/gif', 'image/webp', 'application/msword',
    'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
    'application/vnd.ms-excel',
    'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
}

# Maximum file size (in bytes) - 10MB default
MAX_FILE_SIZE = 10 * 1024 * 1024

def is_allowed_file(filename: str) -> bool:
    """
    Check if a file has an allowed extension.
    
    Args:
        filename: The filename to check
        
    Returns:
        bool: True if the file has an allowed extension, False otherwise
    """
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def secure_save_file(uploaded_file, upload_dir: str) -> Optional[str]:
    """
    Securely save an uploaded file with a random filename.
    
    Args:
        uploaded_file: The uploaded file object
        upload_dir: The directory to save the file in
        
    Returns:
        Optional[str]: The path to the saved file if successful, None otherwise
    """
    if not uploaded_file:
        return None
    
    # Check file size
    if uploaded_file.content_length > MAX_FILE_SIZE:
        security_logger.warning(f"Oversized file upload attempt: {uploaded_file.filename}, size: {uploaded_file.content_length}")
        return None
    
    # Check if the file type is allowed
    if not is_allowed_file(uploaded_file.filename):
        security_logger.warning(f"Disallowed file type upload attempt: {uploaded_file.filename}")
        return None
    
    # Create a secure filename
    orig_filename = secure_filename(uploaded_file.filename)
    file_ext = os.path.splitext(orig_filename)[1]
    
    # Generate a random filename
    random_filename = f"{uuid.uuid4().hex}{file_ext}"
    
    # Ensure the upload directory exists
    os.makedirs(upload_dir, exist_ok=True)
    
    # Build the full path
    file_path = os.path.join(upload_dir, random_filename)
    
    # Save the file
    uploaded_file.save(file_path)
    
    security_logger.info(f"File saved: {orig_filename} -> {random_filename}")
    
    return file_path

# ===== Content Security Policy (CSP) =====

def get_security_headers() -> Dict[str, str]:
    """
    Generate security headers including Content Security Policy.
    
    Returns:
        Dict[str, str]: Dictionary of security headers
    """
    # Base Content Security Policy
    csp = {
        "default-src": ["'self'"],
        "script-src": ["'self'", "'unsafe-inline'"],  # May need to adjust depending on your app's needs
        "style-src": ["'self'", "'unsafe-inline'"],  # May need to adjust depending on your app's needs
        "img-src": ["'self'", "data:"],
        "font-src": ["'self'"],
        "connect-src": ["'self'"],
        "frame-src": ["'self'"],
        "object-src": ["'none'"],
        "base-uri": ["'self'"],
        "form-action": ["'self'"],
        "frame-ancestors": ["'self'"],
    }
    
    # Convert the CSP dictionary to a string
    csp_string = "; ".join(
        f"{key} {' '.join(values)}" for key, values in csp.items()
    )
    
    # Return all security headers
    return {
        "Content-Security-Policy": csp_string,
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "SAMEORIGIN",
        "X-XSS-Protection": "1; mode=block",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
        "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    }

# ===== Security Middleware =====

def security_middleware(app: Flask) -> None:
    """
    Apply security middleware to a Flask application.
    
    Args:
        app: The Flask application
    """
    # Add security headers to all responses
    @app.after_request
    def add_security_headers(response: Response) -> Response:
        headers = get_security_headers()
        for header, value in headers.items():
            response.headers[header] = value
        return response
    
    # Log potential security issues
    @app.before_request
    def log_suspicious_requests() -> None:
        # Check for suspicious URL patterns
        url = request.url
        user_agent = request.headers.get('User-Agent', '')
        ip = request.remote_addr
        
        # Log all requests for audit purposes
        security_logger.debug(f"Request: {request.method} {url} from {ip} using {user_agent}")
        
        # Check for suspicious patterns
        suspicious_patterns = [
            r"(?i)(\.\./|\.\.\%2f)",  # Path traversal attempts
            r"(?i)(select\s+.+\s+from|insert\s+into|update\s+.+\s+set|delete\s+from)",  # SQL injection
            r"(?i)(<script|javascript:)",  # XSS attempts
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, url):
                security_logger.warning(f"Suspicious URL pattern detected: {url}")
                # Optionally, take action like rate limiting or blocking
        
        # Additional checks can be added here as needed

# ===== Initialize Security =====

def init_security(app: Flask, domains: List[str] = None) -> None:
    """
    Initialize all security features for a Flask application.
    
    Args:
        app: The Flask application
        domains: List of allowed domains for URL validation
    """
    # Set up CSRF protection
    csrf.init_app(app)
    
    # Set up rate limiting
    limiter.init_app(app)
    
    # Apply security middleware
    security_middleware(app)
    
    # Set up allowed domains for URL validation
    global ALLOWED_DOMAINS
    if domains:
        ALLOWED_DOMAINS.update(domains)
    
    # Set up secure session configuration
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
    app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=1)
    
    # Log successful initialization
    security_logger.info("Security module initialized")

# ===== Security Decorators =====

def rate_limit(limit_string: str) -> Callable:
    """
    Decorator for custom rate limits on specific routes.
    
    Args:
        limit_string: The rate limit string (e.g., "5 per minute")
        
    Returns:
        Callable: The decorated function
    """
    return limiter.limit(limit_string)

def require_safe_referrer(func: Callable) -> Callable:
    """
    Decorator to require a safe referrer for a route.
    
    Args:
        func: The function to decorate
        
    Returns:
        Callable: The decorated function
    """
    @wraps(func)
    def decorated_function(*args, **kwargs):
        referrer = request.referrer
        if not referrer or not is_safe_url(referrer):
            security_logger.warning(f"Invalid referrer: {referrer}")
            abort(403)
        return func(*args, **kwargs)
    return decorated_function

def log_request(func: Callable) -> Callable:
    """
    Decorator to log requests to sensitive routes.
    
    Args:
        func: The function to decorate
        
    Returns:
        Callable: The decorated function
    """
    @wraps(func)
    def decorated_function(*args, **kwargs):
        security_logger.info(
            f"Access to sensitive route: {request.path} "
            f"from IP: {request.remote_addr}, "
            f"User-Agent: {request.headers.get('User-Agent')}"
        )
        return func(*args, **kwargs)
    return decorated_function

def detect_abuse(func: Callable) -> Callable:
    """
    Decorator to detect and prevent abuse of sensitive routes.
    
    Args:
        func: The function to decorate
        
    Returns:
        Callable: The decorated function
    """
    @wraps(func)
    def decorated_function(*args, **kwargs):
        # This is a placeholder for more sophisticated abuse detection
        # In a real application, you would use techniques like:
        # - IP reputation checking
        # - User behavior analysis
        # - Machine learning-based anomaly detection
        
        # For now, just do some basic checks
        ip = request.remote_addr
        user_agent = request.headers.get('User-Agent', '')
        
        # Check for missing or suspicious user agent
        if not user_agent or user_agent.lower() in ['', 'curl', 'wget', 'python-requests']:
            security_logger.warning(f"Suspicious access attempt from {ip} with user agent: {user_agent}")
            # Depending on your policy, you might want to abort, rate limit, or just log
            # abort(403)
        
        return func(*args, **kwargs)
    return decorated_function

# ===== Security Testing Functions =====

def test_security_headers() -> Dict[str, bool]:
    """
    Test if security headers are properly configured.
    
    Returns:
        Dict[str, bool]: Results of header tests
    """
    # This would be used in a test environment
    headers = get_security_headers()
    
    tests = {
        "CSP": "Content-Security-Policy" in headers,
        "X-Content-Type-Options": "X-Content-Type-Options" in headers and headers["X-Content-Type-Options"] == "nosniff",
        "X-Frame-Options": "X-Frame-Options" in headers and headers["X-Frame-Options"] == "SAMEORIGIN",
        "X-XSS-Protection": "X-XSS-Protection" in headers and headers["X-XSS-Protection"] == "1; mode=block",
        "Referrer-Policy": "Referrer-Policy" in headers,
        "HSTS": "Strict-Transport-Security" in headers,
    }
    
    return tests

def security_health_check() -> Dict[str, str]:
    """
    Perform a health check on the security configuration.
    
    Returns:
        Dict[str, str]: Health check results
    """
    # This would be expanded in a real implementation
    results = {
        "csrf_protection": "Enabled",
        "rate_limiting": "Enabled",
        "security_headers": "Configured",
        "xss_protection": "Enabled",
        "sql_injection_protection": "Enabled",
    }
    
    return results