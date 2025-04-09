import os
import logging
from elasticsearch import Elasticsearch
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_login import LoginManager
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail

# Configure logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

class Base(DeclarativeBase):
    pass

# Initialize extensions
db = SQLAlchemy(model_class=Base)
login_manager = LoginManager()
mail = Mail()

# Create the app
app = Flask(__name__)
app.secret_key = os.environ.get("SESSION_SECRET")
app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1, x_host=1)  # Needed for url_for to generate with https

# Configure the database
app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///app.db")
app.config["SQLALCHEMY_ENGINE_OPTIONS"] = {
    "pool_recycle": 300,
    "pool_pre_ping": True,
}
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# Configure Flask-Login
login_manager.init_app(app)
login_manager.login_view = 'user.login'  # Update with the correct blueprint route
login_manager.login_message = 'Please log in to access this page.'
login_manager.login_message_category = 'info'

# Configure Flask-Mail
app.config['MAIL_SERVER'] = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.environ.get('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_DEFAULT_SENDER', 'noreply@example.com')
mail.init_app(app)

# Use memory storage for rate limiting since Redis might not be available
logger.info("Using in-memory storage for rate limiting")
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Initialize Elasticsearch
elasticsearch_host = os.environ.get('ELASTICSEARCH_HOST', 'localhost')
elasticsearch_port = int(os.environ.get('ELASTICSEARCH_PORT', 9200))
elasticsearch_url = f"http://{elasticsearch_host}:{elasticsearch_port}"

try:
    es = Elasticsearch([elasticsearch_url])
    if es.ping():
        logger.info("Connected to Elasticsearch")
    else:
        logger.warning("Could not connect to Elasticsearch")
        es = None
except Exception as e:
    logger.error(f"Error connecting to Elasticsearch: {e}")
    es = None

# Initialize the app with the extensions
db.init_app(app)

# Import models and create tables
with app.app_context():
    from models import User, Role, Notification, PasswordResetToken, TwoFactorToken  # noqa: F401
    db.create_all()

    # Create default roles if they don't exist
    from models import Role
    admin_role = Role.query.filter_by(name='admin').first()
    if not admin_role:
        admin_role = Role(name='admin', description='Administrator')
        db.session.add(admin_role)
    
    user_role = Role.query.filter_by(name='user').first()
    if not user_role:
        user_role = Role(name='user', description='Regular User')
        db.session.add(user_role)
    
    db.session.commit()

# Import and register blueprints
from userFunctions import user_bp
from adminFunctions import admin_bp
from errorHandlers import register_error_handlers

app.register_blueprint(user_bp)
app.register_blueprint(admin_bp)
register_error_handlers(app)

# Load user callback for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    from models import User
    return User.query.get(int(user_id))
