"""
Rate limiting module for protecting against brute force and DoS attacks.

This module provides rate limiting utilities and decorators for use with Flask
applications, protecting sensitive routes like authentication and APIs.
"""

import logging
import time
import functools
from typing import Dict, Any, Optional, Callable, List, Tuple, Set, Union

from flask import request, abort, current_app, jsonify, g
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Setup rate limiting logger
rate_logger = logging.getLogger("app.rate_limiting")
rate_logger.setLevel(logging.INFO)

# Initialize limiter globally but don't configure yet
limiter = Limiter(key_func=get_remote_address)

# Configurable rate limits for different route types
RATE_LIMITS = {
    'default': "200 per day, 50 per hour",
    'strict': "100 per day, 20 per hour, 5 per minute",
    'auth': "10 per minute, 100 per day",
    'user': "5 per second, 300 per minute",
    'api': "60 per minute, 1000 per day",
    'sensitive': "3 per minute, 10 per hour",
}

# Track failed attempts for advanced security
FAILED_ATTEMPTS: Dict[str, List[float]] = {}

# Time window for tracking failed attempts (seconds)
FAILED_ATTEMPTS_WINDOW = 3600  # 1 hour

# Thresholds for additional security measures
FAILED_ATTEMPTS_THRESHOLD = {
    'login': 5,      # Login attempts
    'password': 3,   # Password reset attempts
    'api': 10,       # API access attempts
}

def init_rate_limiting(app, redis_url: str = None) -> None:
    """
    Initialize rate limiting for a Flask application.
    
    Args:
        app: The Flask application
        redis_url: Redis URL for storage (if None, in-memory storage is used)
    """
    if redis_url:
        from flask_limiter.util import get_ipaddr
        storage_uri = f"redis://{redis_url}"
        
        # Configure limiter with Redis storage
        limiter.init_app(
            app,
            key_func=get_ipaddr,
            storage_uri=storage_uri,
            strategy="fixed-window-elastic-expiry"
        )
        
        rate_logger.info(f"Rate limiting initialized with Redis storage at {redis_url}")
    else:
        # Configure with in-memory storage (not recommended for production)
        limiter.init_app(app)
        rate_logger.warning(
            "Rate limiting initialized with in-memory storage. "
            "This is not recommended for production use."
        )
    
    # Set default limits
    limiter.default_limits = [RATE_LIMITS['default']]

def limit_by_ip(limits: Union[str, List[str]]) -> Callable:
    """
    Apply rate limits based on IP address.
    
    Args:
        limits: Rate limit string(s)
        
    Returns:
        Callable: Decorator function
    """
    return limiter.limit(
        limits,
        key_func=get_remote_address
    )

def limit_by_user(limits: Union[str, List[str]]) -> Callable:
    """
    Apply rate limits based on user ID.
    
    Args:
        limits: Rate limit string(s)
        
    Returns:
        Callable: Decorator function
    """
    def get_user_key():
        # Get the current user ID if available, fallback to IP
        user_id = getattr(g, 'user_id', None)
        if user_id:
            return f"user:{user_id}"
        return get_remote_address()
        
    return limiter.limit(
        limits,
        key_func=get_user_key
    )

def limit_reset_password() -> Callable:
    """
    Rate limit decorator specifically for password reset.
    
    Returns:
        Callable: Decorator function
    """
    return limit_by_ip(RATE_LIMITS['sensitive'])

def limit_login_attempts() -> Callable:
    """
    Rate limit decorator specifically for login attempts.
    
    Returns:
        Callable: Decorator function
    """
    return limit_by_ip(RATE_LIMITS['auth'])

def limit_api_access() -> Callable:
    """
    Rate limit decorator specifically for API access.
    
    Returns:
        Callable: Decorator function
    """
    return limit_by_ip(RATE_LIMITS['api'])

def record_failed_attempt(attempt_type: str, identifier: str) -> None:
    """
    Record a failed attempt for enhanced brute force protection.
    
    Args:
        attempt_type: Type of attempt (login, password, api)
        identifier: Identifier (IP, user ID, etc.)
    """
    key = f"{attempt_type}:{identifier}"
    current_time = time.time()
    
    # Initialize if not exists
    if key not in FAILED_ATTEMPTS:
        FAILED_ATTEMPTS[key] = []
        
    # Add the current attempt
    FAILED_ATTEMPTS[key].append(current_time)
    
    # Cleanup old attempts outside the window
    window_start = current_time - FAILED_ATTEMPTS_WINDOW
    FAILED_ATTEMPTS[key] = [t for t in FAILED_ATTEMPTS[key] if t >= window_start]
    
    # Check if threshold is exceeded
    count = len(FAILED_ATTEMPTS[key])
    threshold = FAILED_ATTEMPTS_THRESHOLD.get(attempt_type, 5)
    
    if count >= threshold:
        rate_logger.warning(
            f"Threshold exceeded for {attempt_type} attempts by {identifier}: "
            f"{count} attempts in the last hour"
        )
        # Additional actions could be taken here:
        # - Require CAPTCHA
        # - Temporary lockout
        # - Notify administrators

def clear_failed_attempts(attempt_type: str, identifier: str) -> None:
    """
    Clear failed attempts after successful action.
    
    Args:
        attempt_type: Type of attempt (login, password, api)
        identifier: Identifier (IP, user ID, etc.)
    """
    key = f"{attempt_type}:{identifier}"
    FAILED_ATTEMPTS.pop(key, None)

def check_failed_attempts(attempt_type: str, identifier: str) -> Tuple[bool, int]:
    """
    Check if number of failed attempts exceeds threshold.
    
    Args:
        attempt_type: Type of attempt (login, password, api)
        identifier: Identifier (IP, user ID, etc.)
        
    Returns:
        Tuple[bool, int]: (Is threshold exceeded, number of attempts)
    """
    key = f"{attempt_type}:{identifier}"
    threshold = FAILED_ATTEMPTS_THRESHOLD.get(attempt_type, 5)
    
    # Get current attempts
    attempts = FAILED_ATTEMPTS.get(key, [])
    
    # Clean up old attempts
    current_time = time.time()
    window_start = current_time - FAILED_ATTEMPTS_WINDOW
    valid_attempts = [t for t in attempts if t >= window_start]
    
    # Update the stored attempts
    if key in FAILED_ATTEMPTS:
        FAILED_ATTEMPTS[key] = valid_attempts
        
    count = len(valid_attempts)
    exceeded = count >= threshold
    
    return exceeded, count

def limit_with_sliding_window(attempt_type: str) -> Callable:
    """
    Create a sliding window rate limiter for specific actions.
    
    Args:
        attempt_type: Type of attempt (login, password, api)
        
    Returns:
        Callable: Decorator function
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Use IP address as identifier
            identifier = get_remote_address()
            
            # Check if threshold is exceeded
            exceeded, count = check_failed_attempts(attempt_type, identifier)
            
            threshold = FAILED_ATTEMPTS_THRESHOLD.get(attempt_type, 5)
            remaining = max(0, threshold - count)
            
            # Set headers for rate limit info
            g.rate_limit_info = {
                'limit': threshold,
                'remaining': remaining,
                'reset': FAILED_ATTEMPTS_WINDOW
            }
            
            if exceeded:
                rate_logger.warning(
                    f"Rate limit exceeded for {attempt_type} by {identifier}: "
                    f"{count} attempts"
                )
                
                # Determine how long they need to wait
                if count > 0:
                    oldest_attempt = min(FAILED_ATTEMPTS.get(f"{attempt_type}:{identifier}", [time.time()]))
                    wait_time = int(oldest_attempt + FAILED_ATTEMPTS_WINDOW - time.time())
                else:
                    wait_time = FAILED_ATTEMPTS_WINDOW
                    
                # You can customize the response based on your needs
                return jsonify({
                    'error': 'Too many attempts',
                    'wait_time': wait_time,
                    'retryAfter': wait_time
                }), 429
                
            # Call the original function
            return func(*args, **kwargs)
            
        return wrapper
    return decorator

def dynamic_rate_limit(func: Callable) -> Callable:
    """
    Apply dynamic rate limits based on user behavior and risk.
    
    Args:
        func: The function to decorate
        
    Returns:
        Callable: The decorated function
    """
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        # Get the user or IP
        user_id = getattr(g, 'user_id', None)
        ip = get_remote_address()
        
        # Simple risk calculation (should be more sophisticated in production)
        risk_factor = 1.0
        
        # Increase risk for unusual IPs, user agents, etc.
        user_agent = request.headers.get('User-Agent', '')
        if not user_agent or len(user_agent) < 10:
            risk_factor *= 2.0
            
        # Adjust risk based on failed attempts
        if user_id:
            _, count = check_failed_attempts('login', f"user:{user_id}")
            risk_factor += count * 0.5
            
        _, count = check_failed_attempts('login', ip)
        risk_factor += count * 0.5
        
        # If risk is high, apply stricter rate limiting
        if risk_factor > 5.0:
            rate_logger.warning(f"High risk factor ({risk_factor}) for {ip}, applying strict rate limit")
            
            # Check if this would exceed the strict limit
            for rule in limiter.get_application_limits(func.__name__, RATE_LIMITS['strict']):
                limited, context = limiter.limiter.get_is_limited(rule, ip)
                if limited:
                    rate_logger.warning(f"Strict rate limit exceeded for {ip}")
                    return jsonify({'error': 'Rate limit exceeded', 'retry_after': context.get('retry_after', 60)}), 429
                    
        # Call the original function
        return func(*args, **kwargs)
        
    return wrapper

def add_rate_limit_headers(response) -> None:
    """
    Add rate limit headers to a response.
    
    Args:
        response: The response object to modify
    """
    if hasattr(g, 'rate_limit_info'):
        info = g.rate_limit_info
        response.headers['X-RateLimit-Limit'] = str(info['limit'])
        response.headers['X-RateLimit-Remaining'] = str(info['remaining'])
        response.headers['X-RateLimit-Reset'] = str(info['reset'])
        
def create_rate_limit_response(wait_time: int) -> Tuple[Dict[str, Any], int]:
    """
    Create a standard rate limit exceeded response.
    
    Args:
        wait_time: The time to wait in seconds
        
    Returns:
        Tuple[Dict[str, Any], int]: The response body and status code
    """
    response = {
        'error': 'Rate limit exceeded',
        'message': f'Too many requests. Please try again in {wait_time} seconds.',
        'retryAfter': wait_time
    }
    return response, 429