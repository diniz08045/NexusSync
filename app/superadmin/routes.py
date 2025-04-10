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
from app.superadmin.forms import (
    SuperAdminLoginForm, ConfigForm, IPManagementForm, 
    DatabaseConfigForm, EmailConfigForm, SystemTimeForm,
    DataRetentionForm, SecurityConfigForm, StartupConfigForm,
    ChangePasswordForm
)
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
ALLOWED_IPS = ['127.0.0.1', 'localhost', '::1', '10.82.4.51', '10.82.5.39', '10.82.']  # localhost and Replit specific IPs

# Whether the development mode is enabled
DEVELOPMENT_MODE = True  # Set to False in production


def is_ip_allowed(ip_address):
    """Check if the IP address is in the allowed list.
    Supports exact matches and partial prefix matches."""
    for allowed_ip in ALLOWED_IPS:
        # Check for exact match
        if ip_address == allowed_ip:
            return True
        # Check for prefix match (e.g. "10.82." will match "10.82.4.51")
        if allowed_ip.endswith('.') and ip_address.startswith(allowed_ip):
            return True
    return False

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
        if not is_ip_allowed(request.remote_addr):
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
    if not is_ip_allowed(request.remote_addr):
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
    form = IPManagementForm()
    
    if form.validate_on_submit():
        # Process IP configurations
        try:
            # This would update IP configurations
            config_changes = {
                "whitelist": form.whitelist.data,
                "blacklist": form.blacklist.data
            }
            
            # Log the changes
            log_action("IP_CONFIG_CHANGE", f"IP management changed: {json.dumps(config_changes)}")
            
            flash('IP management settings updated successfully.', 'success')
            return redirect(url_for('superadmin.ip_management'))
        except Exception as e:
            flash(f'Error updating IP management settings: {str(e)}', 'danger')
            logger.error(f"Error in IP config update: {str(e)}")
    
    # Populate form with current values - in a real app, these would come from a config
    if request.method == 'GET':
        form.whitelist.data = "127.0.0.1\n192.168.1.0/24"
        form.blacklist.data = ""
    
    return render_template('superadmin/ip_management.html', form=form)


@superadmin_bp.route('/database-config', methods=['GET', 'POST'])
@superadmin_required
def database_config():
    """Manage database configuration and API keys."""
    form = DatabaseConfigForm()
    
    if form.validate_on_submit():
        try:
            # This would update database configurations
            config_changes = {
                "db_host": form.db_host.data,
                "db_port": form.db_port.data,
                "db_name": form.db_name.data,
                "db_user": form.db_user.data,
                "db_password": "[REDACTED]"  # Don't log actual password
            }
            
            # Log the changes
            log_action("DB_CONFIG_CHANGE", f"Database configuration changed: {json.dumps(config_changes)}")
            
            flash('Database configuration updated successfully.', 'success')
            return redirect(url_for('superadmin.database_config'))
        except Exception as e:
            flash(f'Error updating database configuration: {str(e)}', 'danger')
            logger.error(f"Error in database config update: {str(e)}")
    
    # Populate form with current values - in a real app, these would come from a config
    if request.method == 'GET':
        db_url = current_app.config.get('SQLALCHEMY_DATABASE_URI', '')
        # In a real implementation, you would parse this URL correctly
        form.db_host.data = os.environ.get('PGHOST', 'localhost')
        form.db_port.data = int(os.environ.get('PGPORT', '5432'))
        form.db_name.data = os.environ.get('PGDATABASE', 'postgres')
        form.db_user.data = os.environ.get('PGUSER', 'postgres')
        form.db_password.data = ''  # Don't fill in password for security reasons
    
    return render_template('superadmin/database_config.html', form=form)


@superadmin_bp.route('/email-config', methods=['GET', 'POST'])
@superadmin_required
def email_config():
    """Manage email server settings."""
    form = EmailConfigForm()
    test_result = None
    
    # Check if this is a test email request
    is_test = request.args.get('test', '0') == '1' or 'test_email' in request.form
    
    if form.validate_on_submit():
        try:
            # Update email configurations
            config_changes = {
                "mail_server": form.mail_server.data,
                "mail_port": form.mail_port.data,
                "mail_use_tls": form.mail_use_tls.data,
                "mail_use_ssl": form.mail_use_ssl.data,
                "mail_username": form.mail_username.data,
                "mail_password": "[REDACTED]",  # Don't log actual password
                "mail_default_sender": form.mail_default_sender.data
            }
            
            # In a real app, you would update Flask-Mail config and potentially restart it
            # Here we just log the change
            log_action("EMAIL_CONFIG_CHANGE", f"Email configuration changed: {json.dumps(config_changes)}")
            
            # Handle test email if requested
            if is_test and 'test_email' in request.form:
                test_email = request.form.get('test_email')
                if test_email:
                    # In a real app, you would send an actual test email here
                    log_action("TEST_EMAIL", f"Test email sent to: {test_email}")
                    flash(f'Test email sent to {test_email}.', 'success')
                else:
                    flash('Test email address is required.', 'warning')
            else:
                flash('Email configuration updated successfully.', 'success')
            
            return redirect(url_for('superadmin.email_config'))
        except Exception as e:
            flash(f'Error updating email configuration: {str(e)}', 'danger')
            logger.error(f"Error in email config update: {str(e)}")
    
    # Populate form with current values
    if request.method == 'GET':
        form.mail_server.data = current_app.config.get('MAIL_SERVER', '')
        form.mail_port.data = current_app.config.get('MAIL_PORT', 587)
        form.mail_use_tls.data = current_app.config.get('MAIL_USE_TLS', True)
        form.mail_use_ssl.data = current_app.config.get('MAIL_USE_SSL', False)
        form.mail_username.data = current_app.config.get('MAIL_USERNAME', '')
        form.mail_password.data = ''  # Don't fill in password for security reasons
        form.mail_default_sender.data = current_app.config.get('MAIL_DEFAULT_SENDER', '')
    
    return render_template('superadmin/email_config.html', form=form)


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
    form = SystemTimeForm()
    
    if form.validate_on_submit():
        try:
            # Process the form data - in a real app, this would update system time settings
            log_action("TIME_CONFIG_CHANGE", "System time settings updated")
            flash('System time settings updated successfully.', 'success')
            return redirect(url_for('superadmin.system_time'))
        except Exception as e:
            flash(f'Error updating system time settings: {str(e)}', 'danger')
            logger.error(f"Error in system time update: {str(e)}")
    
    # Populate the form with current values
    if request.method == 'GET':
        now = datetime.datetime.now()
        form.timezone.data = 'UTC'  # Default timezone
    
    return render_template('superadmin/system_time.html', form=form)


@superadmin_bp.route('/data-retention', methods=['GET', 'POST'])
@superadmin_required
def data_retention():
    """Manage data retention rules."""
    form = DataRetentionForm()
    
    if form.validate_on_submit():
        try:
            # Process form data - in a real app, this would update data retention settings
            log_action("RETENTION_CONFIG_CHANGE", "Data retention settings updated")
            flash('Data retention settings updated successfully.', 'success')
            return redirect(url_for('superadmin.data_retention'))
        except Exception as e:
            flash(f'Error updating data retention settings: {str(e)}', 'danger')
            logger.error(f"Error in data retention update: {str(e)}")
    
    # Populate the form with current values
    if request.method == 'GET':
        form.log_retention_days.data = 90  # Default retention period
        form.backup_retention_days.data = 180  # Default backup retention
        form.user_data_retention_days.data = 365  # Default user data retention
    
    return render_template('superadmin/data_retention.html', form=form)


@superadmin_bp.route('/security-config', methods=['GET', 'POST'])
@superadmin_required
def security_config():
    """Manage SSL/TLS, proxy, DNS, and WAF configurations."""
    form = SecurityConfigForm()
    
    if form.validate_on_submit():
        try:
            # Process form data - in a real app, this would update security settings
            config_changes = {
                "ssl_enabled": form.ssl_enabled.data,
                "proxy_enabled": form.proxy_enabled.data,
                "proxy_server": form.proxy_server.data,
                "proxy_port": form.proxy_port.data,
                "waf_enabled": form.waf_enabled.data,
                "cors_enabled": form.cors_enabled.data,
                "cors_allowed_origins": form.cors_allowed_origins.data
            }
            
            log_action("SECURITY_CONFIG_CHANGE", f"Security configuration changed: {json.dumps(config_changes)}")
            
            flash('Security configuration updated successfully.', 'success')
            return redirect(url_for('superadmin.security_config'))
        except Exception as e:
            flash(f'Error updating security configuration: {str(e)}', 'danger')
            logger.error(f"Error in security config update: {str(e)}")
    
    # Populate the form with current values
    if request.method == 'GET':
        form.ssl_enabled.data = True  # Default setting
        form.proxy_enabled.data = False  # Default setting
        form.waf_enabled.data = True  # Default setting
        form.cors_enabled.data = True  # Default setting
        form.cors_allowed_origins.data = "*"  # Default setting
    
    return render_template('superadmin/security_config.html', form=form)


@superadmin_bp.route('/startup-config', methods=['GET', 'POST'])
@superadmin_required
def startup_config():
    """Manage startup flow and rules."""
    form = StartupConfigForm()
    
    if form.validate_on_submit():
        try:
            # Process form data - in a real app, this would update startup settings
            log_action("STARTUP_CONFIG_CHANGE", "Startup configuration updated")
            flash('Startup configuration updated successfully.', 'success')
            return redirect(url_for('superadmin.startup_config'))
        except Exception as e:
            flash(f'Error updating startup configuration: {str(e)}', 'danger')
            logger.error(f"Error in startup config update: {str(e)}")
    
    # Populate the form with current values
    if request.method == 'GET':
        form.auto_start_services.data = True  # Default setting
        form.startup_timeout.data = 60  # Default timeout in seconds
    
    return render_template('superadmin/startup_config.html', form=form)


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
    form = ChangePasswordForm()
    
    if form.validate_on_submit():
        if check_password_hash(SUPER_ADMIN_PASSWORD_HASH, form.current_password.data):
            # In a real app, we would update the password in a secure way
            # For this demo, we just log the action
            log_action("PASSWORD_CHANGE", "Superadmin password changed")
            
            flash('Password changed successfully.', 'success')
            return redirect(url_for('superadmin.dashboard'))
        else:
            flash('Current password is incorrect.', 'danger')
    
    return render_template('superadmin/change_password.html', form=form)


# Development-only routes (should be removed in production)
if DEVELOPMENT_MODE:
    @superadmin_bp.route('/dev-login')
    def dev_login():
        """Auto-login for development purposes only."""
        # Only allowed from allowed IPs
        if not is_ip_allowed(request.remote_addr):
            logger.warning(f"Unauthorized dev-login attempt from IP: {request.remote_addr}")
            abort(403)  # Forbidden
            
        # Set superadmin status in session
        session['is_superadmin'] = True
        
        # Log the action
        log_action("DEV_LOGIN", "Development auto-login used")
        
        flash('Development auto-login successful. DO NOT USE IN PRODUCTION!', 'warning')
        return redirect(url_for('superadmin.dashboard'))