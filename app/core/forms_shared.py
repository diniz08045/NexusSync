from flask_wtf import FlaskForm
from app.models.user import User
from wtforms import (
    BooleanField,
    EmailField,
    PasswordField,
    SelectField,
    StringField,
    SubmitField,
)
from wtforms.validators import DataRequired, Email, EqualTo, Length, ValidationError


# ================================
# Login Form
# ================================
class LoginForm(FlaskForm):
    """Login form for existing users."""
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    remember_me = BooleanField("Remember Me")
    submit = SubmitField("Sign In")


# ================================
# Registration Form
# ================================
class RegistrationForm(FlaskForm):
    """Form for creating a new user account."""
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=64)])
    email = EmailField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=8)])
    password2 = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo("password")])
    first_name = StringField("First Name", validators=[Length(max=64)])
    last_name = StringField("Last Name", validators=[Length(max=64)])
    department = SelectField("Department", choices=[
        ("default", "General/Default"),
        ("it", "IT Department"),
        ("sales", "Sales Department"),
        ("hr", "Human Resources"),
        ("marketing", "Marketing"),
        ("finance", "Finance/Accounting"),
    ])
    submit = SubmitField("Register")

    def validate_username(self, username):
        """Ensure username is unique."""
        if User.query.filter_by(username=username.data).first():
            raise ValidationError("Please use a different username.")

    def validate_email(self, email):
        """Ensure email address is unique."""
        if User.query.filter_by(email=email.data).first():
            raise ValidationError("Please use a different email address.")


# ================================
# Edit Profile Form
# ================================
class EditProfileForm(FlaskForm):
    """Form for editing user's profile information."""
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=64)])
    email = EmailField("Email", validators=[DataRequired(), Email()])
    first_name = StringField("First Name", validators=[Length(max=64)])
    last_name = StringField("Last Name", validators=[Length(max=64)])
    department = SelectField("Department", choices=[
        ("default", "General/Default"),
        ("it", "IT Department"),
        ("sales", "Sales Department"),
        ("hr", "Human Resources"),
        ("marketing", "Marketing"),
        ("finance", "Finance/Accounting"),
    ])
    submit = SubmitField("Save Changes")

    def __init__(self, original_username, original_email, *args, **kwargs):
        super(EditProfileForm, self).__init__(*args, **kwargs)
        self.original_username = original_username
        self.original_email = original_email

    def validate_username(self, username):
        """Only validate username if it was changed."""
        if username.data != self.original_username:
            if User.query.filter_by(username=username.data).first():
                raise ValidationError("Please use a different username.")

    def validate_email(self, email):
        """Only validate email if it was changed."""
        if email.data != self.original_email:
            if User.query.filter_by(email=email.data).first():
                raise ValidationError("Please use a different email address.")


# ================================
# Password Reset Request Form
# ================================
class PasswordResetRequestForm(FlaskForm):
    """Form to initiate a password reset via email."""
    email = EmailField("Email", validators=[DataRequired(), Email()])
    submit = SubmitField("Reset Password")


# ================================
# Password Reset Form
# ================================
class PasswordResetForm(FlaskForm):
    """Form for setting a new password after token validation."""
    password = PasswordField("New Password", validators=[DataRequired(), Length(min=8)])
    password2 = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo("password")])
    submit = SubmitField("Reset Password")


# ================================
# Two-Factor Authentication Form
# ================================
class TwoFactorForm(FlaskForm):
    """Form for entering 2FA security code."""
    token = StringField("Security Code", validators=[DataRequired(), Length(min=6, max=6)])
    submit = SubmitField("Verify")


# ================================
# Admin User Management Form
# ================================
class AdminUserForm(FlaskForm):
    """Form for admins to edit other users' profiles and roles."""
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=64)])
    email = EmailField("Email", validators=[DataRequired(), Email()])
    first_name = StringField("First Name", validators=[Length(max=64)])
    last_name = StringField("Last Name", validators=[Length(max=64)])
    is_active = BooleanField("Active Account")
    is_email_confirmed = BooleanField("Email Confirmed")
    roles = SelectField("Role", choices=[
        ("user", "Regular User"),
        ("admin", "Administrator")
    ])
    department = SelectField("Department", choices=[
        ("default", "General/Default"),
        ("it", "IT Department"),
        ("sales", "Sales Department"),
        ("hr", "Human Resources"),
        ("marketing", "Marketing"),
        ("finance", "Finance/Accounting"),
    ])
    two_factor_enabled = BooleanField("Two-Factor Authentication Enabled")
    submit = SubmitField("Save Changes")
