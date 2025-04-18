import os
import json

# This class defines all valid configuration keys used across the application.
# These keys are categorized for easier organization and retrieval.
class ConfigKeys:
    # General Application Info
    APPLICATION_NAME            = "APPLICATION_NAME"
    APPLICATION_VERSION         = "APPLICATION_VERSION"
    DEFAULT_LANGUAGE            = "DEFAULT_LANGUAGE"
    TIMEZONE                    = "TIMEZONE"
    DEBUG_MODE                  = "DEBUG_MODE"
    MAINTENANCE_MODE            = "MAINTENANCE_MODE"

    # Security-related settings
    ENFORCE_HTTPS               = "ENFORCE_HTTPS"
    SESSION_TIMEOUT_MINUTES     = "SESSION_TIMEOUT_MINUTES"
    FAILED_LOGIN_LIMIT          = "FAILED_LOGIN_LIMIT"
    ALLOWED_IP_RANGES           = "ALLOWED_IP_RANGES"
    ENABLE_CSP                  = "ENABLE_CSP"
    PASSWORD_COMPLEXITY         = "PASSWORD_COMPLEXITY"
    SESSION_SECRET              = 'SESSION_SECRET'

    # Email and notification settings
    EMAIL_FROM_ADDRESS          = "EMAIL_FROM_ADDRESS"
    SMTP_SERVER                 = "SMTP_SERVER"
    SMTP_PORT                   = "SMTP_PORT"
    SMTP_USE_TLS                = "SMTP_USE_TLS"
    SMTP_USERNAME               = "SMTP_USERNAME"
    SMTP_PASSWORD               = "SMTP_PASSWORD"
    MAIL_DEFAULT_SENDER         = "MAIL_DEFAULT_SENDER"
    ENABLE_EMAIL_NOTIFICATIONS  = "ENABLE_EMAIL_NOTIFICATIONS"
    NOTIFY_ON_NEW_REGISTRATION  = "NOTIFY_ON_NEW_REGISTRATION"
    DEFAULT_NOTIFICATION_LEVEL  = "DEFAULT_NOTIFICATION_LEVEL"

    # User management and access control
    ALLOW_USER_REGISTRATION     = "ALLOW_USER_REGISTRATION"
    REQUIRE_EMAIL_VERIFICATION  = "REQUIRE_EMAIL_VERIFICATION"
    TWO_FACTOR_REQUIRED         = "TWO_FACTOR_REQUIRED"
    DEFAULT_USER_ROLE           = "DEFAULT_USER_ROLE"

    # Feature toggles to enable/disable parts of the app
    ENABLE_API_ACCESS           = "ENABLE_API_ACCESS"
    ENABLE_SEARCH_INDEXING      = "ENABLE_SEARCH_INDEXING"
    ENABLE_ANALYTICS_TRACKING   = "ENABLE_ANALYTICS_TRACKING"
    ENABLE_BACKGROUND_JOBS      = "ENABLE_BACKGROUND_JOBS"
    ENABLE_LIVE_NOTIFICATIONS   = "ENABLE_LIVE_NOTIFICATIONS"

    # File upload and storage options
    FILE_UPLOAD_MAX_SIZE_MB     = "FILE_UPLOAD_MAX_SIZE_MB"
    FILE_STORAGE_BACKEND        = "FILE_STORAGE_BACKEND"

    # Performance tuning
    CACHE_TIMEOUT_SECONDS       = "CACHE_TIMEOUT_SECONDS"
    ENABLE_RATE_LIMITING        = "ENABLE_RATE_LIMITING"
    MAX_CONCURRENT_SESSIONS     = "MAX_CONCURRENT_SESSIONS"

    # Data retention and logging
    DATA_RETENTION_DAYS         = "DATA_RETENTION_DAYS"
    ENABLE_AUDIT_LOGS           = "ENABLE_AUDIT_LOGS"
    LOG_LEVEL                   = "LOG_LEVEL"

    # Branding and appearance
    PRIMARY_COLOR               = "PRIMARY_COLOR"
    LOGO_URL                    = "LOGO_URL"

    # Deployment- or environment-specific values
    ABUSEIPDB_API_KEY           = "ABUSEIPDB_API_KEY"
    SECRET_KEY                  = "SECRET_KEY"
    SQLALCHEMY_DATABASE_URI     = "SQLALCHEMY_DATABASE_URI"
    SQLALCHEMY_ENGINE_OPTIONS   = "SQLALCHEMY_ENGINE_OPTIONS"
    SESSION_COOKIE_SECURE       = "SESSION_COOKIE_SECURE"
    SESSION_COOKIE_HTTPONLY     = "SESSION_COOKIE_HTTPONLY"
    SESSION_COOKIE_SAMESITE     = "SESSION_COOKIE_SAMESITE"
    MAX_CONTENT_LENGTH          = "MAX_CONTENT_LENGTH"
    GEOIP_DB_PATH               = "GEOIP_DB_PATH"
    GEOIP_ASN_DB_PATH           = "GEOIP_ASN_DB_PATH"
    GEOIP_COUNTRY_DB_PATH       = "GEOIP_COUNTRY_DB_PATH"
    SIEM_ENDPOINTS              = "SIEM_ENDPOINTS"


# --- Helper functions to cast config values to the correct data types ---

def to_bool(v):
    """Converts a value to a boolean based on common truthy representations."""
    return str(v).strip().lower() in ["true", "1", "enabled", "yes"]

def to_int(v, default=0):
    """Attempts to convert a value to an integer, returns default on failure."""
    try:
        return int(v)
    except (ValueError, TypeError):
        return default

def to_float(v, default=0.0):
    """Attempts to convert a value to float, returns default on failure."""
    try:
        return float(v)
    except (ValueError, TypeError):
        return default

def to_str(v):
    """Cleans up string input, strips whitespace, and handles None values."""
    return str(v).strip() if v is not None else ""


# --- Mapping config keys to their respective casting functions ---

CONFIG_CASTS = {
    # Booleans
    ConfigKeys.DEBUG_MODE: to_bool,
    ConfigKeys.MAINTENANCE_MODE: to_bool,
    ConfigKeys.ENFORCE_HTTPS: to_bool,
    ConfigKeys.ENABLE_CSP: to_bool,
    ConfigKeys.ENABLE_EMAIL_NOTIFICATIONS: to_bool,
    ConfigKeys.NOTIFY_ON_NEW_REGISTRATION: to_bool,
    ConfigKeys.REQUIRE_EMAIL_VERIFICATION: to_bool,
    ConfigKeys.TWO_FACTOR_REQUIRED: to_bool,
    ConfigKeys.ENABLE_API_ACCESS: to_bool,
    ConfigKeys.ENABLE_SEARCH_INDEXING: to_bool,
    ConfigKeys.ENABLE_ANALYTICS_TRACKING: to_bool,
    ConfigKeys.ENABLE_BACKGROUND_JOBS: to_bool,
    ConfigKeys.ENABLE_LIVE_NOTIFICATIONS: to_bool,
    ConfigKeys.ENABLE_RATE_LIMITING: to_bool,
    ConfigKeys.ENABLE_AUDIT_LOGS: to_bool,
    ConfigKeys.SMTP_USE_TLS: to_bool,
    ConfigKeys.SESSION_COOKIE_SECURE: to_bool,
    ConfigKeys.SESSION_COOKIE_HTTPONLY: to_bool,

    # Integers with default fallbacks
    ConfigKeys.SESSION_TIMEOUT_MINUTES: lambda v: to_int(v, default=30),
    ConfigKeys.FAILED_LOGIN_LIMIT: lambda v: to_int(v, default=5),
    ConfigKeys.SMTP_PORT: lambda v: to_int(v, default=587),
    ConfigKeys.FILE_UPLOAD_MAX_SIZE_MB: lambda v: to_int(v, default=10),
    ConfigKeys.CACHE_TIMEOUT_SECONDS: lambda v: to_int(v, default=60),
    ConfigKeys.MAX_CONCURRENT_SESSIONS: lambda v: to_int(v, default=3),
    ConfigKeys.DATA_RETENTION_DAYS: lambda v: to_int(v, default=90),
    ConfigKeys.MAX_CONTENT_LENGTH: lambda v: to_int(v, default=10 * 1024 * 1024),

    # Strings
    ConfigKeys.APPLICATION_NAME: to_str,
    ConfigKeys.APPLICATION_VERSION: to_str,
    ConfigKeys.DEFAULT_LANGUAGE: to_str,
    ConfigKeys.DEFAULT_USER_ROLE: to_str,
    ConfigKeys.EMAIL_FROM_ADDRESS: to_str,
    ConfigKeys.SMTP_SERVER: to_str,
    ConfigKeys.SMTP_USERNAME: to_str,
    ConfigKeys.SMTP_PASSWORD: to_str,
    ConfigKeys.MAIL_DEFAULT_SENDER: to_str,
    ConfigKeys.DEFAULT_NOTIFICATION_LEVEL: to_str,
    ConfigKeys.PASSWORD_COMPLEXITY: to_str,
    ConfigKeys.TIMEZONE: to_str,
    ConfigKeys.ALLOWED_IP_RANGES: to_str,

    # Environment/Infra related
    ConfigKeys.ABUSEIPDB_API_KEY: to_str,
    ConfigKeys.SECRET_KEY: to_str,
    ConfigKeys.SQLALCHEMY_DATABASE_URI: to_str,
    ConfigKeys.SESSION_COOKIE_SAMESITE: to_str,
    ConfigKeys.GEOIP_DB_PATH: to_str,
    ConfigKeys.GEOIP_ASN_DB_PATH: to_str,
    ConfigKeys.GEOIP_COUNTRY_DB_PATH: to_str,
    ConfigKeys.SIEM_ENDPOINTS: lambda v: json.loads(v) if v else {},
}


# --- Default values to be used when environment variables or DB entries are missing ---

DEFAULTS = {
    ConfigKeys.ABUSEIPDB_API_KEY:    "REDACTED",
    ConfigKeys.SECRET_KEY:           "dev-insecure-secret-key",
    ConfigKeys.SQLALCHEMY_DATABASE_URI:
        f"sqlite:///{os.path.join(os.getcwd(), 'instance', 'app.db')}",
    ConfigKeys.SQLALCHEMY_ENGINE_OPTIONS:
        {"pool_recycle": 300, "pool_pre_ping": True},
    ConfigKeys.SMTP_SERVER:          "smtp.sendgrid.net",
    ConfigKeys.SMTP_PORT:            "587",
    ConfigKeys.SMTP_USE_TLS:         "True",
    ConfigKeys.SMTP_USERNAME:        "apikey",
    ConfigKeys.SMTP_PASSWORD:        None,
    ConfigKeys.MAIL_DEFAULT_SENDER:  "noreply@nexussync.com",
    ConfigKeys.SESSION_COOKIE_SECURE:    "True",
    ConfigKeys.SESSION_COOKIE_HTTPONLY:  "True",
    ConfigKeys.SESSION_COOKIE_SAMESITE:  "Lax",
    ConfigKeys.MAX_CONTENT_LENGTH:       str(10 * 1024 * 1024),
    ConfigKeys.APPLICATION_NAME:     "NexusSync",
    ConfigKeys.GEOIP_DB_PATH:
        os.path.join(os.getcwd(), "instance", "GeoLite2-City.mmdb"),
    ConfigKeys.GEOIP_ASN_DB_PATH:
        os.path.join(os.getcwd(), "instance", "GeoLite2-ASN.mmdb"),
    ConfigKeys.GEOIP_COUNTRY_DB_PATH:
        os.path.join(os.getcwd(), "instance", "GeoLite2-Country.mmdb"),
    ConfigKeys.SIEM_ENDPOINTS:       "{}",
}


def load_env_defaults(app):
    """
    Load system-wide configuration from environment variables.
    If not found in env, fall back to hardcoded default values.
    Automatically casts the values to the appropriate type based on CONFIG_CASTS.
    """
    for key, default in DEFAULTS.items():
        raw = os.getenv(key, default)  # Try loading from environment
        caster = CONFIG_CASTS.get(key)  # Get type-casting function for this key

        try:
            # Apply caster if available, fallback to raw value
            app.config[key] = caster(raw) if caster else raw
        except Exception:
            # Fallback to default if casting fails
            app.logger.warning(f"Bad default for {key}={raw!r}, using {default!r}")
            app.config[key] = default

        app.logger.debug(f"load_env_defaults → {key} = {app.config[key]!r}")


def load_config_from_db(app):
    """
    Loads system configuration from the database and stores it into app.config.
    Skips any entries with empty values. Applies basic smart casting.
    """
    from app.blueprints.superadmin.models.system_config import SystemConfig

    with app.app_context():
        for conf in SystemConfig.query.all():
            key = conf.key.upper()
            val = conf.value

            # Skip empty/null config values
            if val is None or val.strip() == "":
                continue

            # Smart type conversion for known fields
            if key in ('DEBUG_MODE', 'MAINTENANCE_MODE', 'ENABLE_CSP'):
                val = val.lower() in ('1', 'true', 'yes', 'on')
            elif key.endswith('_MINUTES') or key.endswith('_SECONDS') or key in ('FAILED_LOGIN_LIMIT',):
                val = int(val)

            # Save to app.config
            app.config[key] = val
