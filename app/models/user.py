from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from app import db
from app.models.role import user_roles

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    first_name = db.Column(db.String(64))
    last_name = db.Column(db.String(64))
    is_active = db.Column(db.Boolean, default=True)
    is_email_confirmed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime)
    last_ip = db.Column(db.String(45))  # IPv6 can be up to 45 chars
    last_user_agent = db.Column(db.String(256))
    two_factor_enabled = db.Column(db.Boolean, default=False)
    
    # Relationships
    roles = db.relationship('Role', secondary=user_roles, backref=db.backref('users', lazy='dynamic'))
    notifications = db.relationship('Notification', backref='user', lazy='dynamic')
    password_reset_tokens = db.relationship('PasswordResetToken', backref='user', lazy='dynamic')
    two_factor_tokens = db.relationship('TwoFactorToken', backref='user', lazy='dynamic')
    
    def set_password(self, password):
        """Set the user's password."""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check the user's password."""
        return check_password_hash(self.password_hash, password)
    
    def add_role(self, role):
        """Add a role to the user."""
        if not self.has_role(role.name):
            self.roles.append(role)
    
    def remove_role(self, role):
        """Remove a role from the user."""
        if self.has_role(role.name):
            self.roles.remove(role)
    
    def has_role(self, role_name):
        """Check if the user has a role."""
        return any(role.name == role_name for role in self.roles)
    
    def is_admin(self):
        """Check if the user is an admin."""
        return self.has_role('admin')
    
    def unread_notifications_count(self):
        """Get the count of unread notifications."""
        return self.notifications.filter_by(is_read=False, is_dismissed=False).count()
    
    def to_dict(self):
        """Convert user to dictionary."""
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'is_active': self.is_active,
            'is_email_confirmed': self.is_email_confirmed,
            'created_at': self.created_at.isoformat(),
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'two_factor_enabled': self.two_factor_enabled,
            'roles': [role.name for role in self.roles]
        }
    
    def __repr__(self):
        return f'<User {self.username}>'


class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    
    @staticmethod
    def generate_token():
        """Generate a random token."""
        import secrets
        return secrets.token_urlsafe(48)
    
    def __repr__(self):
        return f'<PasswordResetToken {self.id}>'


class TwoFactorToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    
    @staticmethod
    def generate_token():
        """Generate a random 6-digit token."""
        import random
        return str(random.randint(100000, 999999))
    
    def __repr__(self):
        return f'<TwoFactorToken {self.id}>'