"""
Forms for the Superadmin blueprint.
These WTForms classes define structured inputs for configuration, login,
query execution, security controls, and system behaviors.
"""

import pytz
from flask_wtf import FlaskForm
from wtforms import (
    BooleanField,
    IntegerField,
    PasswordField,
    SelectField,
    StringField,
    SubmitField,
    TextAreaField,
)
from wtforms.validators import DataRequired, Email, Length, Optional, ValidationError


# -------------------------------
# Login Form for Superadmin
# -------------------------------
class SuperAdminLoginForm(FlaskForm):
    """Form to handle Superadmin login."""
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


# -------------------------------
# Application Configuration Form
# -------------------------------
class ConfigForm(FlaskForm):
    """Form for managing general application settings."""
    app_name = StringField("Application Name", validators=[DataRequired()])
    debug_mode = BooleanField("Enable Debug Mode")
    maintenance_mode = BooleanField("Enable Maintenance Mode")

    # Timezone dropdown populated with all timezones
    timezone = SelectField(
        "Default Timezone",
        choices=[(tz, tz) for tz in pytz.all_timezones],
        validators=[DataRequired()],
    )

    submit = SubmitField("Save Settings")


# -------------------------------
# System Timezone Configuration
# -------------------------------
class SystemTimeForm(FlaskForm):
    """Form to set system timezone."""
    timezone = SelectField(
        'Timezone',
        choices=[(tz, tz) for tz in pytz.all_timezones],
        validators=[DataRequired()]
    )
    submit = SubmitField('Save Time')


# -------------------------------
# IP Whitelist / Blacklist Form
# -------------------------------
class IPManagementForm(FlaskForm):
    """Form to manage IP access control."""
    whitelist = TextAreaField(
        "Allowed IPs (one per line)",
        validators=[Optional()],
        render_kw={"rows": 5}
    )
    blacklist = TextAreaField(
        "Blocked IPs (one per line)",
        validators=[Optional()],
        render_kw={"rows": 5}
    )
    submit = SubmitField("Save IP Management")


# -------------------------------
# Database Configuration Form
# -------------------------------
class DatabaseConfigForm(FlaskForm):
    """Form to configure remote database connection."""
    db_host = StringField("Database Host", validators=[DataRequired(), Length(max=128)])
    db_port = IntegerField("Database Port", validators=[DataRequired()])
    db_name = StringField("Database Name", validators=[DataRequired(), Length(max=128)])
    db_user = StringField("Database User", validators=[DataRequired(), Length(max=128)])
    db_password = PasswordField("Database Password", validators=[DataRequired(), Length(max=256)])
    submit = SubmitField("Save")


# -------------------------------
# Raw SQL Query Execution Form
# -------------------------------
class QueryForm(FlaskForm):
    """Form to execute custom SQL queries from UI."""
    query = TextAreaField("SQL Query", validators=[DataRequired()])
    submit = SubmitField("Execute")


# -------------------------------
# CLI Tools Execution Form
# -------------------------------
class CliForm(FlaskForm):
    """Form to run safe predefined CLI commands."""
    command = SelectField(
        "Select Command",
        choices=[
            ("list_configs", "List Configs"),
            ("export_config", "Export Config"),
            ("test_db", "Test DB Connection"),
            # Add additional safe commands if needed
        ],
        validators=[DataRequired()],
    )
    submit = SubmitField("Run Command")


# -------------------------------
# API Key Configuration Form
# -------------------------------
class APIKeyConfigForm(FlaskForm):
    """Form to store and label external service API keys."""
    service_name = StringField("Service Name", validators=[DataRequired()])
    api_key = StringField("API Key", validators=[DataRequired()])
    submit = SubmitField("Save API Key")


# -------------------------------
# Email Configuration Form
# -------------------------------
class EmailConfigForm(FlaskForm):
    """Form for SMTP email server configuration."""
    mail_server = StringField("Mail Server", validators=[DataRequired()])
    mail_port = IntegerField("Mail Port", validators=[DataRequired()])
    mail_use_tls = BooleanField("Use TLS")
    mail_use_ssl = BooleanField("Use SSL")
    mail_username = StringField("Mail Username", validators=[DataRequired()])
    mail_password = PasswordField("Mail Password", validators=[DataRequired()])
    mail_default_sender = StringField(
        "Default Sender", validators=[DataRequired(), Email()]
    )
    submit = SubmitField("Save Email Configuration")


# -------------------------------
# Data Retention Policy Form
# -------------------------------
class DataRetentionForm(FlaskForm):
    """Form to set data retention durations."""
    log_retention_days = IntegerField("Log Retention (days)", validators=[DataRequired()])
    backup_retention_days = IntegerField("Backup Retention (days)", validators=[DataRequired()])
    user_data_retention_days = IntegerField("User Data Retention (days)", validators=[DataRequired()])
    submit = SubmitField("Save Retention Rules")


# -------------------------------
# Security Settings Form
# -------------------------------
class SecurityConfigForm(FlaskForm):
    """Form for managing security-related toggles and firewall settings."""
    ssl_enabled = BooleanField("Enable SSL/TLS")
    proxy_enabled = BooleanField("Enable Proxy")
    proxy_server = StringField("Proxy Server", validators=[Optional()])
    proxy_port = IntegerField("Proxy Port", validators=[Optional()])
    waf_enabled = BooleanField("Enable WAF")
    cors_enabled = BooleanField("Enable CORS")
    cors_allowed_origins = TextAreaField(
        "Allowed Origins (one per line)", validators=[Optional()]
    )
    submit = SubmitField("Save Security Configuration")


# -------------------------------
# Startup Behavior Configuration Form
# -------------------------------
class StartupConfigForm(FlaskForm):
    """Form to control app behavior during startup (automation tasks)."""
    auto_migrate = BooleanField("Auto-migrate Database on Startup")
    auto_create_admin = BooleanField("Auto-create Admin User if None Exists")
    auto_backup = BooleanField("Auto-backup Database on Startup")
    auto_start_services = BooleanField("Auto-start Services on Boot")
    startup_timeout = IntegerField(
        "Startup Timeout (seconds)", validators=[DataRequired()]
    )
    submit = SubmitField("Save Startup Configuration")


# -------------------------------
# Superadmin Change Password Form
# -------------------------------
class ChangePasswordForm(FlaskForm):
    """Form to allow Superadmin to change their password securely."""
    current_password = PasswordField("Current Password", validators=[DataRequired()])
    new_password = PasswordField(
        "New Password", validators=[DataRequired(), Length(min=12)]
    )
    confirm_password = PasswordField("Confirm New Password", validators=[DataRequired()])
    submit = SubmitField("Change Password")

    def validate_confirm_password(self, field):
        """
        Custom validator to ensure password confirmation matches.
        """
        if field.data != self.new_password.data:
            raise ValidationError("Passwords do not match.")
        

class CSRFOnlyForm(FlaskForm):
    pass
