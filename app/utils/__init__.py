"""
Utility modules for the Flask application.

This package provides various utility modules for the application,
including security features, middleware, and helpers.
"""

# Import key components for easy access
from app.utils.security import (
    is_safe_url, safe_redirect, validate_external_url,
    generate_token, verify_token, sanitize_html
)
from app.utils.security_headers import get_security_headers, add_security_headers
from app.utils.token_security import (
    generate_password_reset_token, verify_password_reset_token,
    generate_email_verification_token, verify_email_verification_token
)
from app.utils.xss_protection import sanitize_text, sanitize_json_input
from app.utils.file_security import allowed_file, process_uploaded_file
from app.utils.flask_security_extension import SecurityPlus

# Version of the utils package
__version__ = '1.0.0'