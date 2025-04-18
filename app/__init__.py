import os
import atexit
import logging
from datetime import datetime, timedelta

from flask import Flask
from flask_wtf.csrf import CSRFProtect, generate_csrf
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_talisman import Talisman
from apscheduler.schedulers.background import BackgroundScheduler

# Core app components
from app.extensions import db, mail, login_manager, limiter
from app.blueprints.superadmin.config_keys import (
    load_env_defaults,
    load_config_from_db,
    ConfigKeys,
    DEFAULTS,
)
from app.blueprints.superadmin.cli_config import register_config_cli
from app.blueprints.superadmin.system_monitoring_routes import log_system_metrics
from app.blueprints import main_bp, filters_bp, superadmin_bp
from app.core.error_handlers import register_error_handlers
from app.core.rate_limits import configure_rate_limits
from app.security.intelligence.spamhaus import update_blocked_ip_ranges
from app.security.intelligence.geoip import geoip_manager

# Setup logging for debugging and visibility
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)


def create_app(config=None):
    # Initialize Flask application
    app = Flask(__name__, instance_relative_config=True)

    # Register CLI commands (e.g., config CLI)
    register_config_cli(app)

    # Load default settings from environment or fallbacks
    load_env_defaults(app)
    if config:
        app.config.update(config)

    # Enforce a consistent session cookie name and path
    app.config['SESSION_COOKIE_NAME'] = 'nexussync_session'
    app.config['SESSION_COOKIE_PATH'] = '/'

    # Setup core Flask extensions
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
    db.init_app(app)
    mail.init_app(app)
    login_manager.init_app(app)
    limiter.init_app(app)
    app.rate_limits = configure_rate_limits(limiter)

    # Flask-Login messages
    login_manager.login_view = "auth.login"  # Will be replaced if auth is removed
    login_manager.login_message = "Please log in to access this page."
    login_manager.login_message_category = "info"

    # Load the app secret key and enable CSRF protection
    app.secret_key = app.config.get(ConfigKeys.SECRET_KEY)
    CSRFProtect(app)
    app.jinja_env.globals["csrf_token"] = generate_csrf

    # Set strict Content Security Policy via Flask-Talisman
    csp = {
        "default-src": ["'self'"],
        "script-src": [
            "'self'",
            "https://cdn.jsdelivr.net",
            "https://code.jquery.com",
            "https://cdnjs.cloudflare.com",
            "'unsafe-inline'",
        ],
        "style-src": [
            "'self'",
            "https://cdn.jsdelivr.net",
            "https://cdn.replit.com",
            "https://fonts.googleapis.com",
            "https://cdnjs.cloudflare.com",
            "'unsafe-inline'",
        ],
        "img-src": ["'self'", "data:"],
        "font-src": [
            "'self'",
            "https://cdn.jsdelivr.net",
            "https://fonts.googleapis.com",
            "https://fonts.gstatic.com",
            "https://cdnjs.cloudflare.com",
            "data:",
        ],
        "connect-src": ["'self'"],
    }
    Talisman(app, content_security_policy=csp)

    # Register only the blueprints we want active in this version
    for bp in (main_bp, filters_bp):
        app.register_blueprint(bp)
    app.register_blueprint(superadmin_bp, url_prefix="/superadmin")

    # Setup the app context
    with app.app_context():
        logger.info("DB URI: %s", app.config["SQLALCHEMY_DATABASE_URI"])

        # Auto-create all defined tables
        db.create_all()

        # Ensure basic roles exist (for apps that use roles)
        from app.models.role import Role
        if not Role.query.filter_by(name="admin").first():
            db.session.add(Role(name="admin", description="Administrator"))
        if not Role.query.filter_by(name="user").first():
            db.session.add(Role(name="user", description="Regular User"))
        db.session.commit()

        # Populate default system config values
        from app.blueprints.superadmin.models.system_config import SystemConfig
        for key_const, default_val in DEFAULTS.items():
            if not SystemConfig.query.filter_by(key=key_const).first():
                db.session.add(SystemConfig(
                    key=key_const,
                    value=str(default_val),
                    updated_by=None
                ))
        db.session.commit()

        # Apply config from the DB to app.config
        load_config_from_db(app)

        # Normalize bad SameSite values to safe defaults
        samesite = app.config.get(ConfigKeys.SESSION_COOKIE_SAMESITE)
        if samesite not in ("Strict", "Lax", "None"):
            app.logger.warning(f"Bad SameSite {samesite}, resetting to default")
            app.config[ConfigKeys.SESSION_COOKIE_SAMESITE] = DEFAULTS[ConfigKeys.SESSION_COOKIE_SAMESITE]

        # If the secret key wasn't set properly, create one and save it in DB
        secret = app.config.get(ConfigKeys.SECRET_KEY)
        if not secret:
            secret = os.urandom(24).hex()
            app.config[ConfigKeys.SECRET_KEY] = secret
            cfg = SystemConfig.query.filter_by(key=ConfigKeys.SECRET_KEY).first()
            if cfg:
                cfg.value = secret
            else:
                db.session.add(SystemConfig(key=ConfigKeys.SECRET_KEY, value=secret, updated_by=None))
            db.session.commit()
        app.secret_key = secret

        # Initialize GeoIP manager (for country lookups, analytics, etc.)
        geoip_manager.init_app(app)

    # Register global error handlers (404, 500, etc.)
    register_error_handlers(app)

    # Register user loader for Flask-Login
    @login_manager.user_loader
    def load_user(user_id):
        from app.models.user import User
        return User.query.get(int(user_id))

    # Inject global variables into templates
    @app.context_processor
    def inject_app_name():
        return {"app_name": app.config.get("APPLICATION_NAME")}

    @app.context_processor
    def inject_now():
        return {"now": datetime.utcnow(), "timedelta": timedelta}

    # Start background jobs (CPU/memory logging, spamhaus updates)
    if os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        scheduler = BackgroundScheduler()

        def record_metrics():
            with app.app_context():
                log_system_metrics()

        def refresh_drop():
            with app.app_context():
                update_blocked_ip_ranges()

        scheduler.add_job(record_metrics, trigger="interval", seconds=60)
        scheduler.add_job(refresh_drop, trigger="interval", seconds=600)
        scheduler.start()

        # Make sure the scheduler shuts down cleanly when app exits
        atexit.register(lambda: scheduler.shutdown(wait=False))
        logger.debug("APScheduler started")

    return app
