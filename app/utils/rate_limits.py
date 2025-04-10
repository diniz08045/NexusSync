"""
Rate limiting configuration and utilities.
"""
from flask import request, current_app
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from app.utils.security import get_client_ip

# Define decorators for various rate limits
def configure_rate_limits(limiter):
    """
    Configure decorator functions for different rate limiting scenarios.
    
    Args:
        limiter: The Flask-Limiter instance
        
    Returns:
        dict: Dictionary of rate limiting decorators
    """
    return {
        # More strict limits for security-sensitive endpoints
        'login': limiter.limit(
            "5 per minute; 20 per hour",
            key_func=get_client_ip,
            error_message="Too many login attempts. Please try again later."
        ),
        
        # Very strict limits for password reset to prevent enumeration attacks
        'password_reset': limiter.limit(
            "3 per minute; 10 per hour; 20 per day",
            key_func=get_client_ip,
            error_message="Too many password reset attempts. Please try again later."
        ),
        
        # Limits for registration to prevent spam accounts
        'register': limiter.limit(
            "3 per minute; 5 per hour; 10 per day",
            key_func=get_client_ip,
            error_message="Too many registration attempts. Please try again later."
        ),
        
        # API rate limits
        'api': limiter.limit(
            "30 per minute",
            key_func=get_client_ip,
            error_message="API rate limit exceeded. Please slow down your requests."
        ),
        
        # General rate limits
        'standard': limiter.limit(
            "60 per minute",
            key_func=get_client_ip,
            error_message="Rate limit exceeded. Please slow down your requests."
        )
    }