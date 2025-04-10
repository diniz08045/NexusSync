"""
Security headers module for Flask applications.

This module provides functions to add security headers to Flask responses,
including Content Security Policy (CSP), CORS headers, and other
protective headers to mitigate various attacks.
"""

import logging
from typing import Dict, List, Set, Optional, Union, Any, Callable
from functools import wraps

from flask import Response, request, current_app, g

# Setup security headers logger
headers_logger = logging.getLogger("app.security_headers")
headers_logger.setLevel(logging.INFO)

# Default Content Security Policy settings
DEFAULT_CSP = {
    'default-src': ["'self'", "https:", "http:"],
    'script-src': ["'self'", "'unsafe-inline'", "https:", "http:"],
    'style-src': ["'self'", "'unsafe-inline'", "https:", "http:"],
    'img-src': ["'self'", "data:", "https:", "http:"],
    'font-src': ["'self'", "data:", "https:", "http:"],
    'connect-src': ["'self'", "https:", "http:"],
    'frame-src': ["'self'", "https:", "http:"],
    'object-src': ["'none'"],
    'base-uri': ["'self'"],
    'form-action': ["'self'"],
    'frame-ancestors': ["'self'"],
    'upgrade-insecure-requests': [],
}

# Security header defaults
DEFAULT_SECURITY_HEADERS = {
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'SAMEORIGIN',
    'X-XSS-Protection': '1; mode=block',
    'Referrer-Policy': 'strict-origin-when-cross-origin',
    'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
    'Pragma': 'no-cache',
}

# HTTP Strict Transport Security settings
HSTS_SETTINGS = {
    'max-age': 31536000,  # 1 year in seconds
    'includeSubDomains': True,
    'preload': False,
}

def build_csp_header(csp_directives: Dict[str, List[str]] = None) -> str:
    """
    Build a Content Security Policy header value.
    
    Args:
        csp_directives: Dictionary of CSP directives and their values
        
    Returns:
        str: Formatted CSP header value
    """
    # Start with default directives
    directives = DEFAULT_CSP.copy()
    
    # Update with provided directives if any
    if csp_directives:
        for key, values in csp_directives.items():
            directives[key] = values
            
    # Build the CSP string
    csp_parts = []
    
    for directive, sources in directives.items():
        if sources:
            csp_parts.append(f"{directive} {' '.join(sources)}")
        else:
            csp_parts.append(directive)
            
    return '; '.join(csp_parts)

def build_hsts_header() -> str:
    """
    Build an HTTP Strict Transport Security header value.
    
    Returns:
        str: Formatted HSTS header value
    """
    parts = [f"max-age={HSTS_SETTINGS['max-age']}"]
    
    if HSTS_SETTINGS['includeSubDomains']:
        parts.append('includeSubDomains')
        
    if HSTS_SETTINGS['preload']:
        parts.append('preload')
        
    return '; '.join(parts)

def get_security_headers(
    include_csp: bool = True,
    include_hsts: bool = True,
    custom_csp: Dict[str, List[str]] = None,
    custom_headers: Dict[str, str] = None
) -> Dict[str, str]:
    """
    Get a dictionary of security headers to apply to a response.
    
    Args:
        include_csp: Whether to include CSP header
        include_hsts: Whether to include HSTS header
        custom_csp: Custom CSP directives
        custom_headers: Additional custom headers
        
    Returns:
        Dict[str, str]: Dictionary of security headers
    """
    # Start with default security headers
    headers = DEFAULT_SECURITY_HEADERS.copy()
    
    # Add Content Security Policy if requested
    if include_csp:
        headers['Content-Security-Policy'] = build_csp_header(custom_csp)
        
    # Add HTTP Strict Transport Security if requested
    if include_hsts:
        headers['Strict-Transport-Security'] = build_hsts_header()
        
    # Add Permissions Policy (formerly Feature Policy)
    headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=(), payment=()'
        
    # Add any custom headers
    if custom_headers:
        headers.update(custom_headers)
        
    return headers

def add_security_headers(response: Response) -> Response:
    """
    Add security headers to a Flask response.
    
    Args:
        response: The Flask response
        
    Returns:
        Response: The modified response with security headers
    """
    # Get custom CSP from app config or use default
    custom_csp = current_app.config.get('CONTENT_SECURITY_POLICY')
    
    # Get security headers
    headers = get_security_headers(custom_csp=custom_csp)
    
    # Apply headers to response
    for header, value in headers.items():
        response.headers[header] = value
        
    # Log applied headers if debugging
    if current_app.debug:
        headers_logger.debug(f"Applied security headers: {headers}")
        
    return response

def apply_security_headers() -> Callable:
    """
    Decorator to apply security headers to a Flask route.
    
    Returns:
        Callable: The decorator function
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            response = f(*args, **kwargs)
            return add_security_headers(response)
        return decorated_function
    return decorator

def setup_security_headers_middleware(app) -> None:
    """
    Set up the security headers middleware for a Flask application.
    
    Args:
        app: The Flask application
    """
    @app.after_request
    def apply_security_headers_middleware(response: Response) -> Response:
        # Skip for specific response types (like file downloads)
        if response.mimetype in ('application/octet-stream', 'application/download'):
            return response
            
        # Apply security headers
        return add_security_headers(response)
        
    headers_logger.info("Security headers middleware configured")

def set_cors_headers(
    response: Response,
    allowed_origins: Union[List[str], str] = '*',
    allowed_methods: List[str] = None,
    allowed_headers: List[str] = None,
    allow_credentials: bool = False,
    max_age: int = 86400
) -> Response:
    """
    Set CORS headers on a response.
    
    Args:
        response: The Flask response
        allowed_origins: Allowed origins for CORS
        allowed_methods: Allowed HTTP methods
        allowed_headers: Allowed HTTP headers
        allow_credentials: Whether to allow credentials
        max_age: Max age for CORS preflight requests
        
    Returns:
        Response: The modified response with CORS headers
    """
    # Set Access-Control-Allow-Origin
    if isinstance(allowed_origins, list):
        # If specific origins are provided, check the request origin
        origin = request.headers.get('Origin')
        if origin and origin in allowed_origins:
            response.headers['Access-Control-Allow-Origin'] = origin
    else:
        # Otherwise use the provided value (usually '*')
        response.headers['Access-Control-Allow-Origin'] = allowed_origins
        
    # Set Access-Control-Allow-Methods
    if allowed_methods:
        response.headers['Access-Control-Allow-Methods'] = ', '.join(allowed_methods)
    else:
        response.headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS'
        
    # Set Access-Control-Allow-Headers
    if allowed_headers:
        response.headers['Access-Control-Allow-Headers'] = ', '.join(allowed_headers)
    else:
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization'
        
    # Set Access-Control-Allow-Credentials if needed
    if allow_credentials:
        response.headers['Access-Control-Allow-Credentials'] = 'true'
        
    # Set Access-Control-Max-Age
    response.headers['Access-Control-Max-Age'] = str(max_age)
    
    return response

def set_csp_report_only(response: Response, custom_csp: Dict[str, List[str]] = None) -> Response:
    """
    Set Content-Security-Policy-Report-Only header for testing CSP.
    
    Args:
        response: The Flask response
        custom_csp: Custom CSP directives
        
    Returns:
        Response: The modified response
    """
    # Build the CSP header
    csp_value = build_csp_header(custom_csp)
    
    # Add reporting directive if not present
    if 'report-uri' not in csp_value:
        report_uri = current_app.config.get('CSP_REPORT_URI')
        if report_uri:
            csp_value += f"; report-uri {report_uri}"
            
    # Set the header
    response.headers['Content-Security-Policy-Report-Only'] = csp_value
    
    return response

def remove_sensitive_headers(response: Response) -> Response:
    """
    Remove headers that might leak sensitive information.
    
    Args:
        response: The Flask response
        
    Returns:
        Response: The modified response
    """
    # List of headers that might leak information
    sensitive_headers = [
        'Server',
        'X-Powered-By',
        'X-AspNet-Version',
        'X-AspNetMvc-Version',
    ]
    
    # Remove sensitive headers
    for header in sensitive_headers:
        if header in response.headers:
            del response.headers[header]
            
    return response

def apply_feature_policy(response: Response) -> Response:
    """
    Apply a Feature Policy (Permissions Policy) to a response.
    
    Args:
        response: The Flask response
        
    Returns:
        Response: The modified response
    """
    # Define feature policies
    policy = [
        "camera 'none'",
        "microphone 'none'",
        "geolocation 'none'",
        "payment 'none'",
        "usb 'none'",
        "fullscreen 'self'",
        "display-capture 'none'",
    ]
    
    # Set Feature-Policy header (legacy)
    response.headers['Feature-Policy'] = '; '.join(policy)
    
    # Set modern Permissions-Policy header
    permissions_policy = []
    for p in policy:
        parts = p.split(' ', 1)
        if len(parts) == 2:
            feature, value = parts
            # Convert to new format
            if value == "'none'":
                permissions_policy.append(f"{feature}=()")
            elif value == "'self'":
                permissions_policy.append(f"{feature}=(self)")
                
    response.headers['Permissions-Policy'] = ', '.join(permissions_policy)
    
    return response