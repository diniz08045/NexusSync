# This blueprint object is the entry point for all superadmin routes
from .blueprint import superadmin_bp

# Explicitly import all route and utility modules to ensure they’re registered.
# This ensures their decorators and route handlers are active when Flask loads the app.
from . import (
    main_routes,                # Dashboard, login, and primary superadmin views
    system_config_routes,       # System-wide config settings (env, toggles, etc.)
    ip_management_routes,       # Allow/block IPs, CIDR support, etc.
    audit_logs_routes,          # View + export logs of security-critical actions
    data_retention_routes,      # Control how long logs/backups/user data are kept
    startup_config_routes,      # Manage app startup behavior (auto-migrations, etc.)
    system_monitoring_routes,   # Resource usage graphs and live stats
    security_config_routes,     # WAF, CORS, TLS, and other hardening settings
    security_intel_routes,      # Threat feeds, honeypots, external intelligence
    cli_config_routes,          # CLI-accessible route for config loading/utility
    email_config_routes,        # Email service settings (SMTP, sender identity)
    database_config_routes,     # DB hostname, user, password, port
    decorators,                 # Common wrappers like @superadmin_required
)
