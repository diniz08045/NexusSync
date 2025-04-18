# app/models/__init__.py

# Import model classes from individual modules to expose them at package level.
# This allows simplified imports elsewhere in the app, e.g.:
# from app.models import User, Role

from .threat_intel_models import ThreatIntelEntry, GeoIPBlock, ASNBlock, HoneypotEvent
from .user import User, PasswordResetToken, TwoFactorToken
from .session import SessionActivity
from .role import Role

# Define the public interface of the models package.
# Only classes listed here will be available when using `from app.models import *`
__all__ = [
    "ThreatIntelEntry",
    "GeoIPBlock",
    "ASNBlock",
    "HoneypotEvent",
    "User",
    "PasswordResetToken",
    "TwoFactorToken",
    "SessionActivity",
    "Role",
]
