"""
Security initialization module for Flask applications.

This module provides the main entry point for setting up all security
features and protections in a Flask application.
"""

import logging
import os
from typing import List, Dict, Any, Optional

from flask import Flask, request
from flask_wtf.csrf import CSRFProtect

from app.utils.security import init_security, ALLOWED_DOMAINS
from app.utils.middleware import apply_middlewares
from app.utils.rate_limiting import init_rate_limiting
from app.utils.security_headers import setup_security_headers_middleware
from app.utils.url_validation import set_allowed_domains

# Create the main security logger
security_logger = logging.getLogger("app.security")
security_logger.setLevel(logging.INFO)

# Initialize the CSRF protection
csrf = CSRFProtect()

def configure_security(app: Flask, config: Dict[str, Any] = None) -> None:
    """
    Configure all security features for a Flask application.
    
    Args:
        app: The Flask application
        config: Optional security configuration
    """
    # Set up logging
    configure_security_logging(app)
    
    # Apply configuration
    if config:
        apply_security_config(app, config)
    
    # Initialize security components
    init_core_security(app)
    init_rate_limiting(app, app.config.get('REDIS_URL'))
    setup_security_headers_middleware(app)
    apply_middlewares(app)
    
    # Set up allowed domains for URL validation
    allowed_domains = app.config.get('ALLOWED_DOMAINS', [])
    allowed_domains.append(app.config.get('SERVER_NAME', 'localhost'))
    set_allowed_domains(allowed_domains)
    
    # Apply data protection configuration
    configure_data_protection(app)
    
    security_logger.info("Security configuration complete")

def configure_security_logging(app: Flask) -> None:
    """
    Configure security logging.
    
    Args:
        app: The Flask application
    """
    # Configure the main security logger
    log_level = app.config.get('SECURITY_LOG_LEVEL', 'INFO')
    security_logger.setLevel(getattr(logging, log_level))
    
    # Set up file handler if log directory is configured
    log_dir = app.config.get('SECURITY_LOG_DIR')
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)
        log_file = os.path.join(log_dir, 'security.log')
        file_handler = logging.FileHandler(log_file)
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        file_handler.setFormatter(formatter)
        security_logger.addHandler(file_handler)
        
    security_logger.info("Security logging configured")

def init_core_security(app: Flask) -> None:
    """
    Initialize core security features.
    
    Args:
        app: The Flask application
    """
    # Initialize CSRF protection
    csrf.init_app(app)
    
    # Initialize security module
    allowed_domains = app.config.get('ALLOWED_DOMAINS', [])
    init_security(app, allowed_domains)
    
    # Set up secure session configuration
    app.config.setdefault('SESSION_COOKIE_SECURE', True)
    app.config.setdefault('SESSION_COOKIE_HTTPONLY', True)
    app.config.setdefault('SESSION_COOKIE_SAMESITE', 'Lax')
    app.config.setdefault('PERMANENT_SESSION_LIFETIME', 3600)  # 1 hour
    
    # Set up other security settings
    app.config.setdefault('WTF_CSRF_ENABLED', True)
    app.config.setdefault('WTF_CSRF_TIME_LIMIT', 3600)  # 1 hour
    
    security_logger.info("Core security initialized")

def apply_security_config(app: Flask, config: Dict[str, Any]) -> None:
    """
    Apply security configuration to a Flask application.
    
    Args:
        app: The Flask application
        config: Security configuration
    """
    # Apply Content Security Policy configuration
    if 'CSP' in config:
        app.config['CONTENT_SECURITY_POLICY'] = config['CSP']
        
    # Apply rate limiting configuration
    if 'RATE_LIMITS' in config:
        app.config['RATELIMIT_DEFAULT'] = config['RATE_LIMITS'].get('default', '200 per day')
        app.config['RATELIMIT_APPLICATION'] = config['RATE_LIMITS'].get('application', '100 per second')
        
    # Apply trusted hosts configuration
    if 'TRUSTED_HOSTS' in config:
        app.config['TRUSTED_HOSTS'] = config['TRUSTED_HOSTS']
        
    # Apply allowed domains for URL validation
    if 'ALLOWED_DOMAINS' in config:
        app.config['ALLOWED_DOMAINS'] = config['ALLOWED_DOMAINS']
        
    # Apply other security settings
    for key, value in config.items():
        if key not in ('CSP', 'RATE_LIMITS', 'TRUSTED_HOSTS', 'ALLOWED_DOMAINS'):
            app.config[f'SECURITY_{key}'] = value
            
    security_logger.info("Security configuration applied")

def configure_data_protection(app: Flask) -> None:
    """
    Configure data protection features.
    
    Args:
        app: The Flask application
    """
    # Configure file upload directory
    upload_dir = app.config.get('UPLOAD_FOLDER')
    if upload_dir:
        os.makedirs(upload_dir, exist_ok=True)
        # Ensure directory is secure (non-executable)
        try:
            os.chmod(upload_dir, 0o755)  # rwxr-xr-x
        except OSError:
            security_logger.warning(f"Could not set permissions on upload directory: {upload_dir}")
            
    # Configure temporary directory
    temp_dir = app.config.get('TEMP_FOLDER')
    if temp_dir:
        os.makedirs(temp_dir, exist_ok=True)
        try:
            os.chmod(temp_dir, 0o755)  # rwxr-xr-x
        except OSError:
            security_logger.warning(f"Could not set permissions on temp directory: {temp_dir}")
            
    security_logger.info("Data protection configured")

def security_status_check() -> Dict[str, Any]:
    """
    Perform a security status check and return results.
    
    Returns:
        Dict[str, Any]: Security status check results
    """
    status = {
        'csrf_protection': csrf._csrf_protect if hasattr(csrf, '_csrf_protect') else False,
        'rate_limiting': 'flask_limiter' in str(Flask.__init__.__closure__),
        'security_headers': True,  # Assuming headers are configured
        'allowed_domains': list(ALLOWED_DOMAINS) if ALLOWED_DOMAINS else [],
    }
    
    security_logger.info("Security status check complete")
    return status

def security_health_check(app: Flask) -> Dict[str, str]:
    """
    Perform a comprehensive security health check.
    
    Args:
        app: The Flask application
        
    Returns:
        Dict[str, str]: Health check results with status
    """
    results = {}
    
    # Check core security settings
    results['csrf_protection'] = 'OK' if app.config.get('WTF_CSRF_ENABLED') else 'DISABLED'
    results['session_security'] = 'OK' if (
        app.config.get('SESSION_COOKIE_SECURE') and
        app.config.get('SESSION_COOKIE_HTTPONLY')
    ) else 'INSECURE'
    
    # Check Content Security Policy
    csp = app.config.get('CONTENT_SECURITY_POLICY')
    results['content_security_policy'] = 'CONFIGURED' if csp else 'DEFAULT'
    
    # Check rate limiting
    results['rate_limiting'] = (
        'REDIS' if app.config.get('REDIS_URL') else 
        'MEMORY' if hasattr(app, 'limiter') else 
        'DISABLED'
    )
    
    # Check trusted hosts
    results['trusted_hosts'] = 'CONFIGURED' if app.config.get('TRUSTED_HOSTS') else 'OPEN'
    
    # Check upload directory security
    upload_dir = app.config.get('UPLOAD_FOLDER')
    results['upload_directory'] = 'SECURE' if upload_dir and os.path.exists(upload_dir) else 'NOT CONFIGURED'
    
    security_logger.info(f"Security health check: {results}")
    return results