"""
Superadmin module for managing critical system configurations.
This module is accessible only to hardcoded superuser accounts
and only from localhost or through secure SSH tunnels.
"""

from flask import Blueprint

superadmin_bp = Blueprint('superadmin', __name__, url_prefix='/superadmin',
                         template_folder='templates')

from app.superadmin import routes  # noqa: E402, F401