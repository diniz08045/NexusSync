import logging
from flask import current_app, render_template, request
from flask_mail import Message
from app import mail, db
from datetime import datetime, timedelta
from threading import Thread

# Set up logger
logger = logging.getLogger(__name__)

def send_async_email(app, msg):
    """Send email asynchronously."""
    with app.app_context():
        try:
            mail.send(msg)
            logger.info(f"Email sent to {msg.recipients}")
        except Exception as e:
            logger.error(f"Failed to send email: {str(e)}")

def send_email(subject, recipients, text_body, html_body, sender=None, attachments=None):
    """Send an email with the given subject and body to the recipients."""
    try:
        app = current_app._get_current_object()
        
        if not sender:
            sender = app.config['MAIL_DEFAULT_SENDER']
            
        # Check if we have the required email configs
        if not app.config.get('MAIL_SERVER') or not app.config.get('MAIL_PASSWORD'):
            logger.warning("Email not configured. Would have sent email to: " + ", ".join(recipients))
            # Log email content for debugging
            logger.info(f"Email subject: {subject}")
            logger.info(f"Email body: {text_body}")
            # Don't prevent app from working if email isn't configured
            return True
        
        msg = Message(subject, sender=sender, recipients=recipients)
        msg.body = text_body
        msg.html = html_body
        
        if attachments:
            for attachment in attachments:
                msg.attach(
                    filename=attachment['filename'],
                    content_type=attachment['content_type'],
                    data=attachment['data']
                )
        
        Thread(target=send_async_email, args=(app, msg)).start()
        return True
    except Exception as e:
        logger.error(f"Error preparing email: {str(e)}")
        return False

def send_confirmation_email(user):
    """Send account confirmation email."""
    from itsdangerous import URLSafeTimedSerializer
    
    # Generate token
    serializer = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    token = serializer.dumps(user.email)
    
    # Prepare email
    subject = "NexusSync - Please Confirm Your Email"
    confirm_url = f"{request.host_url.rstrip('/')}/auth/confirm-email/{token}"
    
    text_body = f"""
    Hello {user.username},

    Thank you for registering with NexusSync. Please confirm your email address by clicking the link below:

    {confirm_url}

    This link will expire in 1 hour.

    If you did not register for NexusSync, please ignore this email.

    Best regards,
    The NexusSync Team
    """
    
    html_body = render_template('email/confirm_email.html', 
                               user=user, 
                               confirm_url=confirm_url)
    
    # Send email
    send_email(subject, [user.email], text_body, html_body)
    
    logger.info(f"Confirmation email sent to {user.email}")

def send_password_reset_email(user, token):
    """Send password reset email."""
    # Prepare email
    subject = "NexusSync - Password Reset Request"
    reset_url = f"{request.host_url.rstrip('/')}/auth/reset-password/{token}"
    
    text_body = f"""
    Hello {user.username},

    You have requested to reset your password. Please click the link below to reset your password:

    {reset_url}

    This link will expire in 24 hours.

    If you did not request a password reset, please ignore this email and your password will remain unchanged.

    Best regards,
    The NexusSync Team
    """
    
    html_body = render_template('email/reset_password.html', 
                               user=user, 
                               reset_url=reset_url)
    
    # Send email
    send_email(subject, [user.email], text_body, html_body)
    
    logger.info(f"Password reset email sent to {user.email}")

def send_two_factor_token(email, token):
    """Send two-factor authentication token via email."""
    # Prepare email
    subject = "NexusSync - Your Verification Code"
    
    text_body = f"""
    Hello,

    Your verification code for logging into NexusSync is:

    {token}

    This code will expire in 15 minutes.

    If you did not attempt to log in, please contact support immediately.

    Best regards,
    The NexusSync Team
    """
    
    html_body = render_template('email/two_factor_token.html', token=token)
    
    # Send email
    send_email(subject, [email], text_body, html_body)
    
    logger.info(f"Two-factor token sent to {email}")

def send_notification_email(user, notification):
    """Send notification via email."""
    # Prepare email
    subject = f"NexusSync - {notification.title}"
    
    text_body = f"""
    Hello {user.username},

    {notification.message}

    You can view this and all other notifications in your NexusSync account.

    Best regards,
    The NexusSync Team
    """
    
    html_body = render_template('email/notification.html', 
                               user=user, 
                               notification=notification)
    
    # Send email
    send_email(subject, [user.email], text_body, html_body)
    
    logger.info(f"Notification email sent to {user.email}")