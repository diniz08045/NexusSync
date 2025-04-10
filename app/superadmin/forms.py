"""
Forms for the superadmin blueprint.
"""

from flask_wtf import FlaskForm
from wtforms import (
    StringField, PasswordField, BooleanField, SubmitField, 
    TextAreaField, SelectField, IntegerField, MultipleFileField
)
from wtforms.validators import DataRequired, Optional, Email, Length, ValidationError


class SuperAdminLoginForm(FlaskForm):
    """Form for superadmin login."""
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class ConfigForm(FlaskForm):
    """Form for general system configuration."""
    app_name = StringField('Application Name', validators=[DataRequired(), Length(max=64)])
    debug_mode = BooleanField('Debug Mode')
    maintenance_mode = BooleanField('Maintenance Mode')
    submit = SubmitField('Save Configuration')


class IPManagementForm(FlaskForm):
    """Form for IP address management."""
    whitelist = TextAreaField('IP Whitelist (one per line)')
    blacklist = TextAreaField('IP Blacklist (one per line)')
    submit = SubmitField('Save IP Configuration')


class DatabaseConfigForm(FlaskForm):
    """Form for database configuration."""
    db_host = StringField('Database Host', validators=[DataRequired()])
    db_port = IntegerField('Database Port', validators=[DataRequired()])
    db_name = StringField('Database Name', validators=[DataRequired()])
    db_user = StringField('Database User', validators=[DataRequired()])
    db_password = PasswordField('Database Password', validators=[DataRequired()])
    submit = SubmitField('Save Database Configuration')


class APIKeyConfigForm(FlaskForm):
    """Form for API key configuration."""
    service_name = StringField('Service Name', validators=[DataRequired()])
    api_key = StringField('API Key', validators=[DataRequired()])
    submit = SubmitField('Save API Key')


class EmailConfigForm(FlaskForm):
    """Form for email server configuration."""
    mail_server = StringField('Mail Server', validators=[DataRequired()])
    mail_port = IntegerField('Mail Port', validators=[DataRequired()])
    mail_use_tls = BooleanField('Use TLS')
    mail_use_ssl = BooleanField('Use SSL')
    mail_username = StringField('Mail Username', validators=[DataRequired()])
    mail_password = PasswordField('Mail Password', validators=[DataRequired()])
    mail_default_sender = StringField('Default Sender', validators=[DataRequired(), Email()])
    submit = SubmitField('Save Email Configuration')


class DataRetentionForm(FlaskForm):
    """Form for data retention rules."""
    log_retention_days = IntegerField('Log Retention (days)', validators=[DataRequired()])
    backup_retention_days = IntegerField('Backup Retention (days)', validators=[DataRequired()])
    user_data_retention_days = IntegerField('User Data Retention (days)', validators=[DataRequired()])
    submit = SubmitField('Save Retention Rules')


class SecurityConfigForm(FlaskForm):
    """Form for security configuration."""
    ssl_enabled = BooleanField('Enable SSL/TLS')
    proxy_enabled = BooleanField('Enable Proxy')
    proxy_server = StringField('Proxy Server', validators=[Optional()])
    proxy_port = IntegerField('Proxy Port', validators=[Optional()])
    waf_enabled = BooleanField('Enable WAF')
    cors_enabled = BooleanField('Enable CORS')
    cors_allowed_origins = TextAreaField('Allowed Origins (one per line)', validators=[Optional()])
    submit = SubmitField('Save Security Configuration')


class SystemTimeForm(FlaskForm):
    """Form for system time configuration."""
    timezone = SelectField('Timezone', choices=[
        ('UTC', 'UTC'),
        ('US/Eastern', 'US/Eastern'),
        ('US/Central', 'US/Central'),
        ('US/Mountain', 'US/Mountain'),
        ('US/Pacific', 'US/Pacific'),
        ('Europe/London', 'Europe/London'),
        ('Europe/Paris', 'Europe/Paris'),
        ('Asia/Tokyo', 'Asia/Tokyo'),
        ('Australia/Sydney', 'Australia/Sydney')
    ])
    submit = SubmitField('Save Time Configuration')


class StartupConfigForm(FlaskForm):
    """Form for startup configuration."""
    auto_migrate = BooleanField('Auto-migrate Database on Startup')
    auto_create_admin = BooleanField('Auto-create Admin User if None Exists')
    auto_backup = BooleanField('Auto-backup Database on Startup')
    auto_start_services = BooleanField('Auto-start Services on Boot')
    startup_timeout = IntegerField('Startup Timeout (seconds)', validators=[DataRequired()])
    submit = SubmitField('Save Startup Configuration')


class ChangePasswordForm(FlaskForm):
    """Form for changing superadmin password."""
    current_password = PasswordField('Current Password', validators=[DataRequired()])
    new_password = PasswordField('New Password', validators=[DataRequired(), Length(min=12)])
    confirm_password = PasswordField('Confirm New Password', validators=[DataRequired()])
    submit = SubmitField('Change Password')
    
    def validate_confirm_password(self, field):
        """Ensure passwords match."""
        if field.data != self.new_password.data:
            raise ValidationError('Passwords do not match.')