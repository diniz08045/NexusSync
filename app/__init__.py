import os
import logging
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_mail import Mail
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Create base class for SQLAlchemy models
class Base(DeclarativeBase):
    pass

# Initialize extensions
db = SQLAlchemy(model_class=Base)
login_manager = LoginManager()
mail = Mail()
limiter = Limiter(key_func=get_remote_address)

def create_app(config=None):
    """Create and configure the Flask application"""
    app = Flask(__name__, instance_relative_config=True)
    
    # Default configuration
    app.config.update(
        SECRET_KEY=os.environ.get('SESSION_SECRET', 'dev-key-insecure'),
        SQLALCHEMY_DATABASE_URI=os.environ.get('DATABASE_URL'),
        SQLALCHEMY_ENGINE_OPTIONS={
            'pool_recycle': 300,
            'pool_pre_ping': True,
        },
        MAIL_SERVER=os.environ.get('MAIL_SERVER', 'smtp.sendgrid.net'),
        MAIL_PORT=os.environ.get('MAIL_PORT', 587),
        MAIL_USE_TLS=os.environ.get('MAIL_USE_TLS', True),
        MAIL_USERNAME=os.environ.get('MAIL_USERNAME', 'apikey'),
        MAIL_PASSWORD=os.environ.get('SENDGRID_API_KEY'),
        MAIL_DEFAULT_SENDER=os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@nexussync.com'),
        SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE='Lax',
        MAX_CONTENT_LENGTH=10 * 1024 * 1024,  # 10MB limit for uploads
        APPLICATION_NAME='NexusSync'
    )
    
    # Apply additional configuration if provided
    if config:
        app.config.update(config)
        
    # Use ProxyFix to correct URLs behind proxies
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)
    
    # Initialize extensions with app
    db.init_app(app)
    login_manager.init_app(app)
    mail.init_app(app)
    limiter.init_app(app)
    
    # Configure login manager
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'info'
    
    # Import and register blueprints
    from app.main.routes import main_bp
    from app.auth.routes import auth_bp
    from app.user.routes import user_bp
    from app.admin.routes import admin_bp
    from app.planner.routes import planner_bp
    from app.tickets.routes import tickets_bp
    from app.clients.routes import clients_bp
    from app.utils.filters import filters_bp
    from app.superadmin import superadmin_bp
    
    app.register_blueprint(main_bp)
    app.register_blueprint(auth_bp)
    app.register_blueprint(user_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(planner_bp)
    app.register_blueprint(tickets_bp)
    app.register_blueprint(clients_bp)
    app.register_blueprint(filters_bp)
    app.register_blueprint(superadmin_bp)
    
    # Create tables and initialize database
    with app.app_context():
        # Import models to ensure they're registered with SQLAlchemy
        from app.models.user import User, PasswordResetToken, TwoFactorToken
        from app.models.role import Role
        from app.models.notification import Notification
        from app.models.session import SessionActivity
        from app.models.task import Task
        from app.models.ticket import Ticket, TicketComment
        from app.models.client import Client
        
        db.create_all()
        
        # Create default roles if they don't exist
        if not Role.query.filter_by(name='admin').first():
            admin_role = Role(name='admin', description='Administrator')
            db.session.add(admin_role)
            
        if not Role.query.filter_by(name='user').first():
            user_role = Role(name='user', description='Regular User')
            db.session.add(user_role)
            
        db.session.commit()
    
    # Register error handlers
    from app.utils.error_handlers import register_error_handlers
    register_error_handlers(app)
    
    # User loader for Flask-Login
    @login_manager.user_loader
    def load_user(user_id):
        from app.models.user import User
        return User.query.get(int(user_id))
    
    # Context processors
    @app.context_processor
    def inject_app_name():
        return {'app_name': app.config.get('APPLICATION_NAME')}
    
    @app.context_processor
    def inject_now():
        from datetime import datetime
        return {'now': datetime.utcnow()}
    
    return app