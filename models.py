from app import db
from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
import secrets
import uuid

# Define association table for user-role relationship
user_roles = db.Table('user_roles',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id')),
    db.Column('role_id', db.Integer, db.ForeignKey('role.id'))
)

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
    department = db.Column(db.String(64), index=True, default='default')  # Department for dashboard routing
    
    # Relationships
    roles = db.relationship('Role', secondary=user_roles, backref=db.backref('users', lazy='dynamic'))
    notifications = db.relationship('Notification', backref='user', lazy='dynamic')
    password_reset_tokens = db.relationship('PasswordResetToken', backref='user', lazy='dynamic')
    two_factor_tokens = db.relationship('TwoFactorToken', backref='user', lazy='dynamic')
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def add_role(self, role):
        if role not in self.roles:
            self.roles.append(role)
    
    def remove_role(self, role):
        if role in self.roles:
            self.roles.remove(role)
    
    def has_role(self, role_name):
        return any(role.name == role_name for role in self.roles)
    
    def is_admin(self):
        return self.has_role('admin')
    
    def unread_notifications_count(self):
        return Notification.query.filter_by(user_id=self.id, is_read=False).count()
    
    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'first_name': self.first_name,
            'last_name': self.last_name,
            'is_admin': self.is_admin(),
            'department': self.department,
            'roles': [role.name for role in self.roles]
        }
    
    def __repr__(self):
        return f'<User {self.username}>'

class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    description = db.Column(db.String(256))
    
    def __repr__(self):
        return f'<Role {self.name}>'

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    title = db.Column(db.String(128), nullable=False)
    message = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    is_dismissed = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def to_dict(self):
        return {
            'id': self.id,
            'title': self.title,
            'message': self.message,
            'is_read': self.is_read,
            'is_dismissed': self.is_dismissed,
            'created_at': self.created_at.isoformat(),
        }
    
    def __repr__(self):
        return f'<Notification {self.id}>'

class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    
    @staticmethod
    def generate_token():
        return secrets.token_urlsafe(32)
    
    def __repr__(self):
        return f'<PasswordResetToken {self.token}>'

class TwoFactorToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    
    @staticmethod
    def generate_token():
        return str(uuid.uuid4().int)[:6]
    
    def __repr__(self):
        return f'<TwoFactorToken {self.token}>'

class SessionActivity(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_id = db.Column(db.String(128), nullable=False, index=True)
    ip_address = db.Column(db.String(45), nullable=False)
    user_agent = db.Column(db.String(256), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_activity = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    user = db.relationship('User', backref=db.backref('sessions', lazy='dynamic'))
    
    def __repr__(self):
        return f'<SessionActivity {self.session_id}>'
