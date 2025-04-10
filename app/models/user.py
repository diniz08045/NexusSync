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
    department = db.Column(db.String(64), index=True)  # Department for dashboard routing
    
    # Relationships
    roles = db.relationship('Role', secondary=user_roles, backref=db.backref('users', lazy='dynamic'))
    notifications = db.relationship('Notification', backref='user', lazy='dynamic')
    password_reset_tokens = db.relationship('PasswordResetToken', backref='user', lazy='dynamic')
    two_factor_tokens = db.relationship('TwoFactorToken', backref='user', lazy='dynamic')
    
    def set_password(self, password):
        """Set the user's password."""
        # Using the default method pbkdf2:sha256 which is secure
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check the user's password."""
        return check_password_hash(self.password_hash, password)
        
    def record_login(self, ip_address=None, user_agent=None, successful=True):
        """
        Record a login attempt for the user.
        
        Args:
            ip_address: The IP address of the login attempt
            user_agent: The user agent string from the login attempt
            successful: Whether the login was successful
        """
        from app.models.login_attempt import LoginAttempt
        from app import db
        
        # Record the login attempt
        attempt = LoginAttempt(
            user_id=self.id,
            ip_address=ip_address,
            user_agent=user_agent,
            successful=successful
        )
        db.session.add(attempt)
        
        if successful:
            # Update user's last login information
            self.last_login = datetime.utcnow()
            self.last_ip = ip_address
            self.last_user_agent = user_agent
            
        db.session.commit()
        
    @staticmethod
    def validate_password_complexity(password):
        """
        Validate password complexity:
        - At least 8 characters
        - Contains at least one uppercase letter
        - Contains at least one lowercase letter
        - Contains at least one digit
        - Contains at least one special character
        """
        import re
        
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
            
        if not re.search(r'[A-Z]', password):
            return False, "Password must contain at least one uppercase letter"
            
        if not re.search(r'[a-z]', password):
            return False, "Password must contain at least one lowercase letter"
            
        if not re.search(r'\d', password):
            return False, "Password must contain at least one digit"
            
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False, "Password must contain at least one special character"
            
        return True, "Password meets complexity requirements"
    
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
            'department': self.department,
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
    ip_address = db.Column(db.String(45))  # IP address that requested the reset
    
    @staticmethod
    def generate_token():
        """Generate a random token using the secrets module for cryptographic security."""
        import secrets
        return secrets.token_urlsafe(48)  # 64 bytes of randomness
    
    def is_valid(self):
        """Check if token is valid (not expired and not used)."""
        now = datetime.utcnow()
        return not self.is_used and now < self.expires_at
    
    def invalidate(self):
        """Mark token as used to prevent reuse."""
        self.is_used = True
    
    def __repr__(self):
        return f'<PasswordResetToken {self.id}>'


class TwoFactorToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    attempts = db.Column(db.Integer, default=0)  # Track failed attempts
    ip_address = db.Column(db.String(45))  # IP address used for token request
    
    @staticmethod
    def generate_token():
        """Generate a random 6-digit token using secrets for cryptographic security."""
        import secrets
        # More secure than random.randint
        return str(secrets.randbelow(900000) + 100000)
    
    def is_valid(self):
        """Check if token is valid (not expired, not used, and not too many attempts)."""
        now = datetime.utcnow()
        MAX_ATTEMPTS = 5  # Max number of failed attempts before token is invalid
        return (not self.is_used and 
                now < self.expires_at and 
                self.attempts < MAX_ATTEMPTS)
    
    def increment_attempts(self):
        """Increment failed attempts counter."""
        self.attempts += 1
        
    def invalidate(self):
        """Mark token as used to prevent reuse."""
        self.is_used = True
    
    def __repr__(self):
        return f'<TwoFactorToken {self.id}>'