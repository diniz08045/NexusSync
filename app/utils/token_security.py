"""
Token security module for generating and validating secure tokens.

This module provides functions for creating and validating time-limited,
signed tokens for use in password resets, email verification, and CSRF protection.
"""

import time
import secrets
import logging
import hashlib
import hmac
import base64
from typing import Dict, Any, Optional, Union, Tuple
from datetime import datetime, timedelta

from flask import current_app, session, request
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

# Setup token security logger
token_logger = logging.getLogger("app.token_security")
token_logger.setLevel(logging.INFO)

# Token types
TOKEN_TYPES = {
    'password_reset': {'max_age': 3600, 'prefix': 'pr'},  # 1 hour
    'email_verification': {'max_age': 86400, 'prefix': 'ev'},  # 24 hours
    'two_factor': {'max_age': 600, 'prefix': '2f'},  # 10 minutes
    'api': {'max_age': 900, 'prefix': 'api'},  # 15 minutes
    'invite': {'max_age': 604800, 'prefix': 'inv'},  # 7 days
}

# Token storage for tokens that need to be invalidated after use
# In a production app, this would be a database or Redis cache
USED_TOKENS: Dict[str, datetime] = {}

def clean_used_tokens() -> None:
    """
    Clean up expired tokens from the used tokens store.
    
    This should be called periodically to prevent memory leaks.
    In a production app, this would be handled by database TTL or Redis expiry.
    """
    now = datetime.utcnow()
    expired_tokens = [token for token, expires in USED_TOKENS.items() if expires < now]
    for token in expired_tokens:
        USED_TOKENS.pop(token, None)
        
    token_logger.debug(f"Cleaned {len(expired_tokens)} expired tokens")

def get_token_serializer() -> URLSafeTimedSerializer:
    """
    Get a token serializer configured with the app's secret key.
    
    Returns:
        URLSafeTimedSerializer: Configured serializer
    """
    return URLSafeTimedSerializer(current_app.config['SECRET_KEY'])

def generate_token(data: Dict[str, Any], token_type: str = 'default') -> str:
    """
    Generate a secure, signed token with the specified data.
    
    Args:
        data: The data to include in the token
        token_type: The type of token (determines expiration)
        
    Returns:
        str: The signed token
    """
    # Get token parameters
    token_params = TOKEN_TYPES.get(token_type, {'max_age': 3600, 'prefix': 'df'})
    
    # Add metadata
    token_data = data.copy()
    token_data.update({
        'type': token_type,
        'created': int(time.time()),
        'nonce': secrets.token_hex(8),  # Prevents token reuse
    })
    
    # Serialize and sign
    serializer = get_token_serializer()
    token = f"{token_params['prefix']}_{serializer.dumps(token_data)}"
    
    token_logger.info(f"Generated {token_type} token")
    return token

def verify_token(token: str, token_type: str = None, max_age: int = None) -> Optional[Dict[str, Any]]:
    """
    Verify a token and return its data if valid.
    
    Args:
        token: The token to verify
        token_type: The expected token type (if None, any type is accepted)
        max_age: Maximum age in seconds (overrides token type default)
        
    Returns:
        Optional[Dict[str, Any]]: The token data if valid, None otherwise
    """
    # Check if token has the expected format (prefix_value)
    parts = token.split('_', 1)
    if len(parts) != 2:
        token_logger.warning("Invalid token format")
        return None
        
    prefix, value = parts
    
    # Get token parameters based on prefix
    token_params = None
    for t_type, params in TOKEN_TYPES.items():
        if params['prefix'] == prefix:
            token_params = params
            actual_token_type = t_type
            break
            
    if token_params is None:
        token_logger.warning(f"Unknown token prefix: {prefix}")
        return None
        
    # If a specific token type was requested, verify it matches
    if token_type and actual_token_type != token_type:
        token_logger.warning(f"Token type mismatch: expected {token_type}, got {actual_token_type}")
        return None
        
    # Use provided max_age if specified, otherwise use token type default
    token_max_age = max_age if max_age is not None else token_params['max_age']
    
    # Check if token has been used (for one-time tokens)
    if token in USED_TOKENS:
        token_logger.warning(f"Token already used: {token}")
        return None
        
    # Deserialize and verify
    serializer = get_token_serializer()
    try:
        data = serializer.loads(value, max_age=token_max_age)
        
        # Verify internal token type matches
        if 'type' not in data or data['type'] != actual_token_type:
            token_logger.warning("Token type mismatch in payload")
            return None
            
        token_logger.info(f"Verified {actual_token_type} token")
        return data
    except SignatureExpired:
        token_logger.warning("Token signature expired")
        return None
    except BadSignature:
        token_logger.warning("Invalid token signature")
        return None
    except Exception as e:
        token_logger.error(f"Token verification error: {str(e)}")
        return None

def invalidate_token(token: str, expires_in: int = 86400) -> None:
    """
    Mark a token as used/invalid to prevent reuse.
    
    Args:
        token: The token to invalidate
        expires_in: How long to keep the token in the invalid list (seconds)
    """
    # In a production app, this would store the token in a database or Redis cache
    expiry = datetime.utcnow() + timedelta(seconds=expires_in)
    USED_TOKENS[token] = expiry
    
    token_logger.info(f"Invalidated token {token}")
    
    # Clean up expired tokens periodically
    if len(USED_TOKENS) % 10 == 0:  # Every 10 invalidations
        clean_used_tokens()

def generate_password_reset_token(user_id: int) -> str:
    """
    Generate a token for password reset.
    
    Args:
        user_id: The ID of the user
        
    Returns:
        str: The password reset token
    """
    return generate_token({'user_id': user_id}, token_type='password_reset')

def verify_password_reset_token(token: str) -> Optional[int]:
    """
    Verify a password reset token and return the user ID if valid.
    
    Args:
        token: The token to verify
        
    Returns:
        Optional[int]: The user ID if valid, None otherwise
    """
    data = verify_token(token, token_type='password_reset')
    if data and 'user_id' in data:
        # Mark token as used immediately to prevent reuse
        invalidate_token(token)
        return data['user_id']
    return None

def generate_email_verification_token(user_id: int, email: str) -> str:
    """
    Generate a token for email verification.
    
    Args:
        user_id: The ID of the user
        email: The email to verify
        
    Returns:
        str: The email verification token
    """
    return generate_token({'user_id': user_id, 'email': email}, token_type='email_verification')

def verify_email_verification_token(token: str) -> Optional[Dict[str, Any]]:
    """
    Verify an email verification token and return the user data if valid.
    
    Args:
        token: The token to verify
        
    Returns:
        Optional[Dict[str, Any]]: Dict with user_id and email if valid, None otherwise
    """
    data = verify_token(token, token_type='email_verification')
    if data and 'user_id' in data and 'email' in data:
        # Mark token as used immediately to prevent reuse
        invalidate_token(token)
        return {'user_id': data['user_id'], 'email': data['email']}
    return None

def generate_two_factor_token(user_id: int) -> str:
    """
    Generate a token for two-factor authentication.
    
    Args:
        user_id: The ID of the user
        
    Returns:
        str: The two-factor token
    """
    # For 2FA, we might want to generate a 6-digit numeric code
    code = ''.join(secrets.choice('0123456789') for _ in range(6))
    return generate_token({'user_id': user_id, 'code': code}, token_type='two_factor')

def verify_two_factor_token(token: str, provided_code: str) -> Optional[int]:
    """
    Verify a two-factor authentication token and code.
    
    Args:
        token: The token to verify
        provided_code: The code provided by the user
        
    Returns:
        Optional[int]: The user ID if valid, None otherwise
    """
    data = verify_token(token, token_type='two_factor')
    if data and 'user_id' in data and 'code' in data and data['code'] == provided_code:
        # Mark token as used immediately to prevent reuse
        invalidate_token(token)
        return data['user_id']
    return None

def generate_csrf_token() -> str:
    """
    Generate a CSRF token and store it in the session.
    
    Returns:
        str: The CSRF token
    """
    if 'csrf_token' not in session:
        session['csrf_token'] = secrets.token_hex(32)
    return session['csrf_token']

def verify_csrf_token(token: str) -> bool:
    """
    Verify a CSRF token against the one stored in the session.
    
    Args:
        token: The token to verify
        
    Returns:
        bool: True if valid, False otherwise
    """
    if not token or 'csrf_token' not in session:
        token_logger.warning("CSRF token missing")
        return False
        
    # Use constant-time comparison to prevent timing attacks
    valid = hmac.compare_digest(session['csrf_token'], token)
    if not valid:
        token_logger.warning("CSRF token invalid")
    return valid

def rotate_csrf_token() -> str:
    """
    Rotate the CSRF token to a new value.
    
    Returns:
        str: The new CSRF token
    """
    session.pop('csrf_token', None)
    return generate_csrf_token()

def get_token_from_header() -> Optional[str]:
    """
    Extract a token from the Authorization header.
    
    Returns:
        Optional[str]: The token if present, None otherwise
    """
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        return auth_header[7:]  # Remove 'Bearer ' prefix
    return None

def get_token_from_request() -> Optional[str]:
    """
    Extract a token from the request (header, query param, or form).
    
    Returns:
        Optional[str]: The token if found, None otherwise
    """
    # Try to get from Authorization header
    token = get_token_from_header()
    if token:
        return token
        
    # Try to get from query parameters
    token = request.args.get('token')
    if token:
        return token
        
    # Try to get from form data
    token = request.form.get('token')
    return token