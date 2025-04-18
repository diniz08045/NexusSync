from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from app.extensions import db
from app.models.role import user_roles


# ==========================================
# Model: User
# ==========================================
class User(UserMixin, db.Model):
    """
    Represents a user in the system. Includes authentication, authorization,
    activity tracking, and role-based access control.
    """

    id = db.Column(db.Integer, primary_key=True)

    # Credentials
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)

    # Personal info
    first_name = db.Column(db.String(64))
    last_name = db.Column(db.String(64))
    department = db.Column(db.String(64), index=True)

    # Account status
    is_active = db.Column(db.Boolean, default=True)
    is_email_confirmed = db.Column(db.Boolean, default=False)
    two_factor_enabled = db.Column(db.Boolean, default=False)

    # Activity tracking
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    last_ip = db.Column(db.String(45))  # IPv6-safe
    last_user_agent = db.Column(db.String(256))

    # Relationships
    roles = db.relationship("Role", secondary=user_roles, backref=db.backref("users", lazy="dynamic"))
    password_reset_tokens = db.relationship("PasswordResetToken", backref="user", lazy="dynamic")
    two_factor_tokens = db.relationship("TwoFactorToken", backref="user", lazy="dynamic")

    # ==========================
    # Authentication Methods
    # ==========================
    def set_password(self, password):
        """Hashes and stores the user's password."""
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Validates a raw password against the stored hash."""
        return check_password_hash(self.password_hash, password)

    def record_login(self, ip_address=None, user_agent=None, successful=True):
        """
        Logs a login attempt and updates last login info if successful.
        """
        from app.models.login_attempt import LoginAttempt

        db.session.add(LoginAttempt(
            user_id=self.id,
            ip_address=ip_address,
            user_agent=user_agent,
            successful=successful,
        ))

        if successful:
            self.last_login = datetime.utcnow()
            self.last_ip = ip_address
            self.last_user_agent = user_agent

        db.session.commit()

    @staticmethod
    def validate_password_complexity(password):
        """
        Enforces password strength rules.
        Must include uppercase, lowercase, digit, and special character.
        """
        import re
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        if not re.search(r"[A-Z]", password):
            return False, "Password must contain at least one uppercase letter"
        if not re.search(r"[a-z]", password):
            return False, "Password must contain at least one lowercase letter"
        if not re.search(r"\d", password):
            return False, "Password must contain at least one digit"
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Password must contain at least one special character"
        return True, "Password meets complexity requirements"

    # ==========================
    # Role & Access Control
    # ==========================
    def add_role(self, role):
        """Assigns a role to the user if not already assigned."""
        if not self.has_role(role.name):
            self.roles.append(role)

    def remove_role(self, role):
        """Removes a role from the user if it exists."""
        if self.has_role(role.name):
            self.roles.remove(role)

    def has_role(self, role_name):
        """Returns True if user has a specific role."""
        return any(role.name.lower() == role_name.lower() for role in self.roles)

    def is_admin(self):
        """Check if user has admin role."""
        return self.has_role("admin")

    @property
    def is_superadmin(self):
        """Check if user has superadmin role."""
        return self.has_role("superadmin")

    # ==========================
    # Utility
    # ==========================
    def unread_notifications_count(self):
        """Returns count of unread and undismissed notifications."""
        return self.notifications.filter_by(is_read=False, is_dismissed=False).count()

    def to_dict(self):
        """Serializes user object to dictionary."""
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "is_active": self.is_active,
            "is_email_confirmed": self.is_email_confirmed,
            "created_at": self.created_at.isoformat(),
            "last_login": self.last_login.isoformat() if self.last_login else None,
            "two_factor_enabled": self.two_factor_enabled,
            "department": self.department,
            "roles": [role.name for role in self.roles],
        }

    def __repr__(self):
        return f"<User {self.username}>"


# ==========================================
# Model: PasswordResetToken
# ==========================================
class PasswordResetToken(db.Model):
    """
    Secure one-time token for user password reset requests.
    """

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    ip_address = db.Column(db.String(45))  # IP address that initiated reset

    @staticmethod
    def generate_token():
        """Generate a secure token."""
        import secrets
        return secrets.token_urlsafe(48)

    def is_valid(self):
        """Returns True if token is still valid (not used or expired)."""
        return not self.is_used and datetime.utcnow() < self.expires_at

    def invalidate(self):
        """Marks token as used."""
        self.is_used = True

    def __repr__(self):
        return f"<PasswordResetToken {self.id}>"


# ==========================================
# Model: TwoFactorToken
# ==========================================
class TwoFactorToken(db.Model):
    """
    Temporary token used for 2FA verification.
    """

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    token = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    attempts = db.Column(db.Integer, default=0)  # Number of failed attempts
    ip_address = db.Column(db.String(45))       # IP address of the request

    @staticmethod
    def generate_token():
        """Generate a random 6-digit token (string)."""
        import secrets
        return str(secrets.randbelow(900000) + 100000)

    def is_valid(self):
        """Check if the token is valid for use."""
        return (
            not self.is_used
            and datetime.utcnow() < self.expires_at
            and self.attempts < 5
        )

    def increment_attempts(self):
        """Increment failed attempt counter."""
        self.attempts += 1

    def invalidate(self):
        """Mark token as used."""
        self.is_used = True

    def __repr__(self):
        return f"<TwoFactorToken {self.id}>"
