from functools import wraps
from flask import redirect, url_for, flash
from flask_login import current_user

def check_confirmed_email(func):
    """
    Decorator to check if a user's email is confirmed.
    If not, redirects to profile page with message.
    """
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if not current_user.is_email_confirmed:
            flash('Please confirm your email address before accessing this page.', 'warning')
            return redirect(url_for('user.profile'))
        return func(*args, **kwargs)
    return decorated_function

def admin_required(func):
    """
    Decorator to restrict access to admin users.
    If not admin, redirects to user home with error message.
    """
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin():
            flash('You do not have permission to access this page.', 'danger')
            return redirect(url_for('user.index'))
        return func(*args, **kwargs)
    return decorated_function