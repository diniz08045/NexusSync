from datetime import datetime
from app import db

class LoginAttempt(db.Model):
    """
    Model for tracking login attempts (successful and failed).
    Used for security auditing and to detect suspicious activity.
    """
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ip_address = db.Column(db.String(45))  # IPv6 can be up to 45 chars
    user_agent = db.Column(db.String(256))
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    successful = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        status = "successful" if self.successful else "failed"
        return f"<LoginAttempt {status} for user_id {self.user_id} at {self.timestamp}>"