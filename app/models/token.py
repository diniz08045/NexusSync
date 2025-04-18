import secrets
from datetime import datetime
from app.extensions import db


# ==========================================
# Model: PasswordResetToken
# ==========================================
class PasswordResetToken(db.Model):
    """
    Represents a time-limited, single-use token for securely resetting a user's password.
    """

    id = db.Column(db.Integer, primary_key=True)

    # The user this token belongs to
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    # Unique token string for reset link (indexed for fast lookup)
    token = db.Column(db.String(64), unique=True, nullable=False, index=True)

    # When the token was created
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # When the token will expire
    expires_at = db.Column(db.DateTime, nullable=False)

    # Indicates whether the token has already been used
    is_used = db.Column(db.Boolean, default=False)

    @staticmethod
    def generate_token():
        """
        Generates a secure URL-safe token for password reset.
        Typically used when creating a new PasswordResetToken instance.
        """
        return secrets.token_urlsafe(48)

    def __repr__(self):
        """Readable representation for logging/debugging."""
        return f"<PasswordResetToken {self.token[:8]}...>"


# ==========================================
# Model: TwoFactorToken
# ==========================================
class TwoFactorToken(db.Model):
    """
    Represents a time-sensitive numeric token for 2FA verification.
    Typically used during login to confirm identity after username/password.
    """

    id = db.Column(db.Integer, primary_key=True)

    # The user this token belongs to
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    # 6-digit numeric token (stored as a string)
    token = db.Column(db.String(6), nullable=False)

    # When the token was generated
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # When the token will expire
    expires_at = db.Column(db.DateTime, nullable=False)

    # Indicates whether the token has already been used
    is_used = db.Column(db.Boolean, default=False)

    @staticmethod
    def generate_token():
        """
        Generates a 6-digit numeric token as a string (e.g., '543219').
        """
        return str(secrets.randbelow(900000) + 100000)  # Ensures a 6-digit value

    def __repr__(self):
        """Readable representation for logging/debugging."""
        return f"<TwoFactorToken {self.token}>"
