import secrets
from datetime import datetime, timedelta
from app import db

class PasswordResetToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(64), unique=True, nullable=False, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    
    @staticmethod
    def generate_token():
        """Generate a secure token for password reset."""
        return secrets.token_urlsafe(48)
    
    def __repr__(self):
        return f'<PasswordResetToken {self.token[:8]}...>'

class TwoFactorToken(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    token = db.Column(db.String(6), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    is_used = db.Column(db.Boolean, default=False)
    
    @staticmethod
    def generate_token():
        """Generate a numeric token for two-factor authentication."""
        return str(secrets.randbelow(900000) + 100000)  # 6-digit number
    
    def __repr__(self):
        return f'<TwoFactorToken {self.token}>'