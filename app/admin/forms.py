from flask_wtf import FlaskForm
from wtforms import StringField, BooleanField, SubmitField, EmailField, SelectField, PasswordField, TextAreaField
from wtforms.validators import DataRequired, Email, Length, EqualTo, ValidationError
from app.models.user import User

class AdminUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=64)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    first_name = StringField('First Name', validators=[Length(max=64)])
    last_name = StringField('Last Name', validators=[Length(max=64)])
    is_active = BooleanField('Active Account')
    is_email_confirmed = BooleanField('Email Confirmed')
    roles = SelectField('Role', choices=[])
    two_factor_enabled = BooleanField('Two-Factor Authentication Enabled')
    submit = SubmitField('Save Changes')
    
    def __init__(self, *args, **kwargs):
        super(AdminUserForm, self).__init__(*args, **kwargs)
        self.original_username = kwargs.get('username', '')
        self.original_email = kwargs.get('email', '')
        
    def validate_username(self, username):
        if username.data != self.original_username:
            user = User.query.filter_by(username=username.data).first()
            if user is not None:
                raise ValidationError('Please use a different username.')
    
    def validate_email(self, email):
        if email.data != self.original_email:
            user = User.query.filter_by(email=email.data).first()
            if user is not None:
                raise ValidationError('Please use a different email address.')

class CreateUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=64)])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    first_name = StringField('First Name', validators=[Length(max=64)])
    last_name = StringField('Last Name', validators=[Length(max=64)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    password2 = PasswordField(
        'Confirm Password', validators=[DataRequired(), EqualTo('password')])
    is_active = BooleanField('Active Account', default=True)
    is_email_confirmed = BooleanField('Email Confirmed', default=True)
    roles = SelectField('Role', choices=[])
    two_factor_enabled = BooleanField('Two-Factor Authentication Enabled')
    submit = SubmitField('Create User')
    
    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user is not None:
            raise ValidationError('Please use a different username.')
    
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user is not None:
            raise ValidationError('Please use a different email address.')

class NotificationForm(FlaskForm):
    user = SelectField('User', choices=[], validators=[DataRequired()])
    title = StringField('Title', validators=[DataRequired(), Length(max=128)])
    message = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Send Notification')