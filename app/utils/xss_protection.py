"""
XSS (Cross-Site Scripting) protection module for handling user inputs safely.

This module provides functions to sanitize user inputs, escape HTML content, 
and protect against XSS attacks in Flask applications.
"""

import logging
import re
from typing import Dict, List, Any, Optional, Set, Callable

import bleach
from flask import request, abort
from markupsafe import escape, Markup

# Setup XSS protection logger
xss_logger = logging.getLogger("app.xss_protection")
xss_logger.setLevel(logging.INFO)

# Configuration for HTML sanitization
ALLOWED_TAGS = [
    'a', 'abbr', 'acronym', 'b', 'blockquote', 'br', 'code',
    'div', 'em', 'i', 'li', 'ol', 'p', 'pre', 'span',
    'strong', 'ul', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6',
    'table', 'thead', 'tbody', 'tr', 'th', 'td', 'hr',
]

ALLOWED_ATTRIBUTES = {
    'a': ['href', 'title', 'rel', 'target'],
    'abbr': ['title'],
    'acronym': ['title'],
    'div': ['class', 'id'],
    'span': ['class', 'id'],
    'table': ['class', 'id'],
    'th': ['scope', 'colspan', 'rowspan'],
    'td': ['colspan', 'rowspan'],
    'code': ['class'],
    'pre': ['class'],
    'img': ['src', 'alt', 'title', 'width', 'height', 'class'],
}

ALLOWED_STYLES: List[str] = []

# Link protocols that are allowed
ALLOWED_PROTOCOLS = ['http', 'https', 'mailto', 'tel']

def sanitize_html(html_content: str, strict: bool = True) -> str:
    """
    Sanitize HTML content to prevent XSS attacks.
    
    Args:
        html_content: The HTML content to sanitize
        strict: Whether to use strict sanitization (fewer tags allowed)
        
    Returns:
        str: The sanitized HTML content
    """
    if not html_content:
        return ""
        
    # For strict mode, reduce the allowed tags
    tags = ALLOWED_TAGS
    if strict:
        tags = ['a', 'b', 'br', 'code', 'div', 'em', 'i', 'p', 'span', 'strong']
        
    # Apply bleach sanitization
    cleaned = bleach.clean(
        html_content,
        tags=tags,
        attributes=ALLOWED_ATTRIBUTES,
        styles=ALLOWED_STYLES,
        protocols=ALLOWED_PROTOCOLS,
        strip=True,
        strip_comments=True
    )
    
    return cleaned

def sanitize_text(text: str) -> str:
    """
    Sanitize plain text by removing any HTML tags completely.
    
    Args:
        text: The text to sanitize
        
    Returns:
        str: The sanitized text
    """
    if not text:
        return ""
        
    # First use bleach to strip all HTML
    no_html = bleach.clean(text, tags=[], strip=True)
    
    # Then escape any remaining special characters
    return str(escape(no_html))

def sanitize_filename(filename: str) -> str:
    """
    Sanitize a filename to prevent path traversal and injection.
    
    Args:
        filename: The filename to sanitize
        
    Returns:
        str: The sanitized filename
    """
    if not filename:
        return ""
        
    # Remove any directory components
    filename = re.sub(r'[/\\]', '', filename)
    
    # Remove special characters
    filename = re.sub(r'[^a-zA-Z0-9_.-]', '_', filename)
    
    # Ensure the filename doesn't start with a dot (hidden file)
    if filename.startswith('.'):
        filename = '_' + filename
        
    return filename

def sanitize_json_input(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Recursively sanitize values in a JSON object.
    
    Args:
        data: The JSON data to sanitize
        
    Returns:
        Dict[str, Any]: The sanitized JSON data
    """
    result = {}
    
    for key, value in data.items():
        # Sanitize the key (should be a string)
        clean_key = sanitize_text(str(key))
        
        # Recursively sanitize values based on type
        if isinstance(value, dict):
            result[clean_key] = sanitize_json_input(value)
        elif isinstance(value, list):
            result[clean_key] = [
                sanitize_json_input(item) if isinstance(item, dict)
                else sanitize_text(str(item)) if isinstance(item, str)
                else item
                for item in value
            ]
        elif isinstance(value, str):
            result[clean_key] = sanitize_text(value)
        else:
            # For non-string types (numbers, booleans, None), keep as is
            result[clean_key] = value
            
    return result

def sanitize_form_input() -> Dict[str, str]:
    """
    Sanitize all form input from a request.
    
    Returns:
        Dict[str, str]: Dictionary of sanitized form values
    """
    result = {}
    
    for key, value in request.form.items():
        # Skip CSRF token and other special fields
        if key == 'csrf_token':
            result[key] = value
            continue
            
        # Sanitize regular form fields
        result[key] = sanitize_text(value)
        
    return result

def sanitize_url(url: str) -> str:
    """
    Sanitize a URL to prevent javascript: and other dangerous protocols.
    
    Args:
        url: The URL to sanitize
        
    Returns:
        str: The sanitized URL
    """
    if not url:
        return ""
        
    # Parse the URL to check its components
    parts = re.match(r'^((?P<scheme>[^:]+):)?(//(?P<netloc>[^/]*))?', url)
    
    # If there's a scheme, make sure it's allowed
    if parts and parts.group('scheme'):
        scheme = parts.group('scheme').lower()
        if scheme not in ALLOWED_PROTOCOLS:
            xss_logger.warning(f"Blocked URL with dangerous scheme: {url}")
            return "#"  # Return a harmless fragment
            
    return url

def xss_protect(func: Callable) -> Callable:
    """
    Decorator to protect a route from XSS by sanitizing all incoming data.
    
    Args:
        func: The function to decorate
        
    Returns:
        Callable: The decorated function
    """
    def decorated_function(*args, **kwargs):
        # Check for suspicious patterns in request data
        suspicious_patterns = [
            r"<script",
            r"javascript:",
            r"onerror=",
            r"onload=",
            r"onclick=",
            r"data:text/html",
        ]
        
        # Look for patterns in URL parameters
        for param, value in request.args.items():
            if not isinstance(value, str):
                continue
                
            for pattern in suspicious_patterns:
                if re.search(pattern, value, re.IGNORECASE):
                    xss_logger.warning(f"Potential XSS attack detected in URL parameter: {param}={value}")
                    abort(400, "Invalid input detected")
                    
        # Look for patterns in form data
        for param, value in request.form.items():
            if not isinstance(value, str):
                continue
                
            for pattern in suspicious_patterns:
                if re.search(pattern, value, re.IGNORECASE):
                    xss_logger.warning(f"Potential XSS attack detected in form data: {param}={value}")
                    abort(400, "Invalid input detected")
                    
        # Continue to the original function
        return func(*args, **kwargs)
        
    return decorated_function

def safe_json_response(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Ensure a JSON response is safe from XSS.
    
    Args:
        data: The JSON data to sanitize
        
    Returns:
        Dict[str, Any]: The sanitized JSON data
    """
    return sanitize_json_input(data)

def detect_xss_attacks(request_data) -> bool:
    """
    Detect potential XSS attacks in request data.
    
    Args:
        request_data: The request data to check
        
    Returns:
        bool: True if potential XSS detected, False otherwise
    """
    # Define patterns that might indicate XSS attacks
    xss_patterns = [
        r'<script[^>]*>',
        r'javascript:',
        r'onmouseover=',
        r'onerror=',
        r'onload=',
        r'onclick=',
        r'<img[^>]+src=[^>]+onerror=',
        r'<iframe[^>]*src=',
        r'eval\s*\(',
        r'document\.cookie',
        r'document\.write',
        r'document\.location',
        r'<svg[^>]*onload=',
        r'expression\s*\(',
        r'url\s*\(',
    ]
    
    # Function to check a string against XSS patterns
    def check_string(s):
        if not isinstance(s, str):
            return False
            
        for pattern in xss_patterns:
            if re.search(pattern, s, re.IGNORECASE):
                xss_logger.warning(f"Potential XSS pattern detected: {pattern} in {s[:50]}...")
                return True
        return False
    
    # Recursive function to check nested data structures
    def check_data(data):
        if isinstance(data, dict):
            return any(check_data(v) for v in data.values())
        elif isinstance(data, list):
            return any(check_data(item) for item in data)
        elif isinstance(data, str):
            return check_string(data)
        return False
    
    # Check the request data
    return check_data(request_data)