# app/blueprints/superadmin/blueprint.py

from flask import Blueprint

# Create the blueprint for the superadmin section of the app.
# This will be used to group all routes, templates, and static files
# related to superadmin functionality.
superadmin_bp = Blueprint(
    "superadmin",
    __name__,
    template_folder="templates/superadmin",
)

# ─────────────────────────────────────────────────────────────
# Register all route files for the superadmin blueprint.
# Make sure each one is only imported once — this ensures their
# route definitions get registered when this file is imported.
# ─────────────────────────────────────────────────────────────

from . import (
    system_config_routes,       # Routes for system-level config settings
    ip_management_routes,       # Routes for IP allow/block management
    data_retention_routes,      # Routes for managing data retention settings
    system_monitoring_routes,   # Routes for system resource monitoring
    main_routes,                # Core routes (e.g., login, dashboard)
    audit_logs_routes,          # Audit log viewing and export
    startup_config_routes,      # Startup behavior configuration
    security_config_routes,     # Routes for configuring security policies
    cli_config_routes,          # CLI-related config endpoints (if any)
    email_config_routes,        # Email server / sender configuration
    database_config_routes,     # Database connection settings
    config_keys,                # Shared constants and casting logic
    cli_config,                 # Optional CLI tools registered via this module
    decorators,                 # Decorators like @superadmin_required
)
