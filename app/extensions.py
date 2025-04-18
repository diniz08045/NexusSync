from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_login import LoginManager
from flask_mail import Mail
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import DeclarativeBase


# ===============================
# Custom Declarative Base for SQLAlchemy
# ===============================

class Base(DeclarativeBase):
    """
    Custom declarative base class for SQLAlchemy models.
    All your models will inherit from this base class to ensure
    consistent metadata and future extensibility.
    """
    pass


# ===============================
# Flask Extensions Initialization
# ===============================

# SQLAlchemy instance for handling all ORM operations
# Uses the custom base class above for model definitions
db = SQLAlchemy(model_class=Base)

# Flask-Login manager for handling user session management
login_manager = LoginManager()

# Flask-Mail instance for handling email sending functionality
mail = Mail()

# Flask-Limiter instance for rate limiting to prevent abuse
# Uses the client's IP address as the unique key
limiter = Limiter(key_func=get_remote_address)
