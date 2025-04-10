"""
Routes for the superadmin blueprint.
These routes are only accessible to hardcoded superuser accounts
and only from localhost or through secure SSH tunnels.
"""

import os
import logging
import json
import datetime
from functools import wraps

from flask import (
    render_template, flash, redirect, url_for, request, 
    current_app, jsonify, abort, session
)
from flask_login import current_user, login_required
from werkzeug.security import check_password_hash, generate_password_hash

from app.models.user import User
from app.superadmin import superadmin_bp
from app.superadmin.forms import SuperAdminLoginForm, ConfigForm
from app import db

# Set up logger
logger = logging.getLogger(__name__)

# Dictionary to store login attempts
login_attempts = {}

# Hardcoded superadmin credentials
# In production, you would likely store this in a more secure way
SUPER_ADMIN_USERNAME = "superadmin"
SUPER_ADMIN_PASSWORD_HASH = generate_password_hash("change_this_password_immediately!")

# Define the list of allowed IP addresses
ALLOWED_IPS = ['127.0.0.1', 'localhost', '::1']  # localhost only


def superadmin_required(f):
    """
    Custom decorator to ensure the user has superadmin privileges.
    This checks:
    1. If the user is authenticated
    2. If the user is coming from an allowed IP
    3. If the user has superadmin privileges in the session
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if the request is coming from an allowed IP
        if request.remote_addr not in ALLOWED_IPS:
            logger.warning(f"Unauthorized superadmin access attempt from IP: {request.remote_addr}")
            abort(403)  # Forbidden
            
        # Check if the user is authenticated and has superadmin privileges
        if not session.get('is_superadmin', False):
            logger.warning(f"Unauthorized superadmin access attempt: {request.path}")
            return redirect(url_for('superadmin.login'))
            
        # Log the access
        logger.info(f"Superadmin access: {request.path} from IP {request.remote_addr}")
        return f(*args, **kwargs)
    return decorated_function


def log_action(action_type, details=""):
    """Log superadmin actions securely."""
    timestamp = datetime.datetime.utcnow().isoformat()
    ip_address = request.remote_addr
    user_agent = request.user_agent.string
    
    log_entry = {
        "timestamp": timestamp,
        "action": action_type,
        "details": details,
        "ip_address": ip_address,
        "user_agent": user_agent
    }
    
    # Log to application logs
    logger.info(f"SUPERADMIN ACTION: {json.dumps(log_entry)}")
    
    # You could also store this in a database or secure file
    log_file = os.path.join(current_app.instance_path, 'superadmin_audit.log')
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    with open(log_file, 'a') as f:
        f.write(json.dumps(log_entry) + "\n")


@superadmin_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Login page for superadmin."""
    # Reset superadmin status
    session['is_superadmin'] = False
    
    # Check if the request is coming from an allowed IP
    if request.remote_addr not in ALLOWED_IPS:
        logger.warning(f"Superadmin login attempt from unauthorized IP: {request.remote_addr}")
        abort(403)  # Forbidden
    
    form = SuperAdminLoginForm()
    
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        # Check for too many failed login attempts
        ip = request.remote_addr
        if ip in login_attempts and login_attempts[ip]['count'] >= 5:
            if (datetime.datetime.utcnow() - login_attempts[ip]['last_attempt']).total_seconds() < 3600:
                flash('Too many failed login attempts. Please try again later.', 'danger')
                logger.warning(f"Too many failed superadmin login attempts from IP: {ip}")
                return render_template('superadmin/login.html', form=form)
            else:
                # Reset counter after lockout period
                login_attempts[ip] = {'count': 0, 'last_attempt': datetime.datetime.utcnow()}
        
        # Validate superadmin credentials
        if username == SUPER_ADMIN_USERNAME and check_password_hash(SUPER_ADMIN_PASSWORD_HASH, password):
            # Log successful login
            log_action("LOGIN", "Successful superadmin login")
            
            # Set superadmin in session
            session['is_superadmin'] = True
            
            # Reset login attempts
            if ip in login_attempts:
                login_attempts[ip] = {'count': 0, 'last_attempt': datetime.datetime.utcnow()}
            
            flash('Logged in successfully as superadmin.', 'success')
            return redirect(url_for('superadmin.dashboard'))
        else:
            # Increment failed login attempts
            if ip not in login_attempts:
                login_attempts[ip] = {'count': 1, 'last_attempt': datetime.datetime.utcnow()}
            else:
                login_attempts[ip]['count'] += 1
                login_attempts[ip]['last_attempt'] = datetime.datetime.utcnow()
            
            # Log failed login attempt
            log_action("FAILED_LOGIN", f"Failed superadmin login with username: {username}")
            
            flash('Invalid username or password.', 'danger')
    
    return render_template('superadmin/login.html', form=form)


@superadmin_bp.route('/logout')
@superadmin_required
def logout():
    """Logout the superadmin."""
    # Log the logout
    log_action("LOGOUT", "Superadmin logout")
    
    # Reset superadmin status
    session['is_superadmin'] = False
    
    flash('You have been logged out.', 'info')
    return redirect(url_for('superadmin.login'))


@superadmin_bp.route('/')
@superadmin_required
def dashboard():
    """Main dashboard for superadmin."""
    return render_template('superadmin/dashboard.html')


@superadmin_bp.route('/system-config', methods=['GET', 'POST'])
@superadmin_required
def system_config():
    """Manage system configurations."""
    form = ConfigForm()
    
    if form.validate_on_submit():
        # Process form submission
        try:
            # Update configurations based on form data
            # This is a placeholder - in a real app, you'd update actual config files
            config_changes = {
                "app_name": form.app_name.data,
                "debug_mode": form.debug_mode.data,
                "maintenance_mode": form.maintenance_mode.data,
                # Add other config fields here
            }
            
            # Log the configuration changes
            log_action("CONFIG_CHANGE", f"System configuration changed: {json.dumps(config_changes)}")
            
            flash('System configuration updated successfully.', 'success')
            return redirect(url_for('superadmin.system_config'))
        except Exception as e:
            flash(f'Error updating system configuration: {str(e)}', 'danger')
            logger.error(f"Error in system config update: {str(e)}")
    
    # Populate form with current values
    if request.method == 'GET':
        form.app_name.data = current_app.config.get('APPLICATION_NAME', 'NexusSync')
        form.debug_mode.data = current_app.config.get('DEBUG', False)
        form.maintenance_mode.data = current_app.config.get('MAINTENANCE_MODE', False)
        # Set other form fields here
    
    return render_template('superadmin/system_config.html', form=form)


@superadmin_bp.route('/ip-management', methods=['GET', 'POST'])
@superadmin_required
def ip_management():
    """Manage IP whitelist/blacklist."""
    # This would be expanded to show current IP lists and allow editing
    return render_template('superadmin/ip_management.html')


@superadmin_bp.route('/database-config', methods=['GET', 'POST'])
@superadmin_required
def database_config():
    """Manage database configuration and API keys."""
    # This would be expanded to show and edit database configuration
    return render_template('superadmin/database_config.html')


@superadmin_bp.route('/email-config', methods=['GET', 'POST'])
@superadmin_required
def email_config():
    """Manage email server settings."""
    # This would be expanded to show and edit email configuration
    return render_template('superadmin/email_config.html')


@superadmin_bp.route('/system-monitoring')
@superadmin_required
def system_monitoring():
    """View system monitoring and usage analytics."""
    # This would be expanded to show system metrics
    return render_template('superadmin/system_monitoring.html')


@superadmin_bp.route('/system-time', methods=['GET', 'POST'])
@superadmin_required
def system_time():
    """Manage system time/date settings."""
    # This would be expanded to show and edit system time settings
    return render_template('superadmin/system_time.html')


@superadmin_bp.route('/data-retention', methods=['GET', 'POST'])
@superadmin_required
def data_retention():
    """Manage data retention rules."""
    # This would be expanded to show and edit data retention settings
    return render_template('superadmin/data_retention.html')


@superadmin_bp.route('/security-config', methods=['GET', 'POST'])
@superadmin_required
def security_config():
    """Manage SSL/TLS, proxy, DNS, and WAF configurations."""
    # This would be expanded to show and edit security settings
    return render_template('superadmin/security_config.html')


@superadmin_bp.route('/startup-config', methods=['GET', 'POST'])
@superadmin_required
def startup_config():
    """Manage startup flow and rules."""
    # This would be expanded to show and edit startup configuration
    return render_template('superadmin/startup_config.html')


@superadmin_bp.route('/audit-logs')
@superadmin_required
def audit_logs():
    """View superadmin audit logs."""
    log_file = os.path.join(current_app.instance_path, 'superadmin_audit.log')
    logs = []
    
    if os.path.exists(log_file):
        with open(log_file, 'r') as f:
            logs = [json.loads(line) for line in f.readlines()]
    
    # Sort logs by timestamp, newest first
    logs.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    
    return render_template('superadmin/audit_logs.html', logs=logs)


@superadmin_bp.route('/change-password', methods=['GET', 'POST'])
@superadmin_required
def change_password():
    """Change the superadmin password."""
    # This would be expanded to allow changing the superadmin password
    return render_template('superadmin/change_password.html')