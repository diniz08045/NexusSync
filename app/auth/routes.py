import logging
from datetime import datetime, timedelta
from flask import Blueprint, render_template, redirect, url_for, flash, request, session, current_app
from flask_login import login_user, logout_user, current_user, login_required
from app import db
from app.models.user import User, PasswordResetToken, TwoFactorToken
from app.models.session import SessionActivity
from app.auth.forms import LoginForm, RegistrationForm, PasswordResetRequestForm, PasswordResetForm, TwoFactorForm
from app.utils.email import send_password_reset_email, send_confirmation_email, send_two_factor_token

# Set up logger
logger = logging.getLogger(__name__)

# Create blueprint
auth_bp = Blueprint('auth', __name__, url_prefix='/auth')

@auth_bp.route('/login', methods=['GET', 'POST'])
@auth_bp.route('/login/', methods=['GET', 'POST'])
def login():
    """User login page."""
    # Apply rate limiting for login attempts
    current_app.rate_limits['login']
    
    if current_user.is_authenticated:
        return redirect(url_for('user.index'))
    
    form = LoginForm()
    
    if form.validate_on_submit():
        # Get client info for security tracking
        ip_address = request.remote_addr
        user_agent = request.user_agent.string if request.user_agent else "Unknown"
        
        user = User.query.filter_by(username=form.username.data).first()
        
        # Check for too many failed attempts
        from app.utils.security import check_login_attempts, log_security_event
        
        if user:
            is_blocked, remaining_time = check_login_attempts(
                user.id, 
                ip_address=ip_address, 
                max_attempts=5,
                window_minutes=15
            )
            
            if is_blocked:
                log_security_event('login_blocked', user_id=user.id, 
                                  details={'reason': 'too_many_attempts', 'ip': ip_address})
                
                flash(f'Account temporarily locked due to too many failed attempts. Please try again later.', 'danger')
                return redirect(url_for('auth.login'))
        
        if user is None or not user.check_password(form.password.data):
            # Record failed login attempt
            if user:
                user.record_login(ip_address, user_agent, successful=False)
                log_security_event('login_failed', user_id=user.id, 
                                  details={'ip': ip_address, 'reason': 'invalid_password'})
            else:
                log_security_event('login_failed', 
                                  details={'username': form.username.data, 'reason': 'user_not_found'})
                
            flash('Invalid username or password.', 'danger')
            logger.warning(f"Failed login attempt for username: {form.username.data} from IP: {ip_address}")
            
            # Delay response to slow down brute force attacks
            import time
            time.sleep(1)
            
            return redirect(url_for('auth.login'))
        
        if not user.is_active:
            log_security_event('login_blocked', user_id=user.id, 
                              details={'reason': 'account_inactive', 'ip': ip_address})
            
            flash('Your account has been deactivated. Please contact the administrator.', 'danger')
            logger.warning(f"Login attempt on inactive account: {user.username} from IP: {ip_address}")
            return redirect(url_for('auth.login'))
        
        # Two-factor authentication check
        if user.two_factor_enabled:
            # Create a 2FA token
            token = TwoFactorToken.generate_token()
            two_factor_token = TwoFactorToken(
                user_id=user.id,
                token=token,
                expires_at=datetime.utcnow() + timedelta(minutes=15)
            )
            db.session.add(two_factor_token)
            db.session.commit()
            
            # Send token to user's email
            send_two_factor_token(user.email, token)
            
            # Store user ID in session for 2FA verification
            session['two_factor_user_id'] = user.id
            
            flash('A verification code has been sent to your email.', 'info')
            return redirect(url_for('auth.two_factor_auth'))
        
        # Check for login from new location or device
        from app.utils.location import check_new_location, check_new_device
        is_new_location = check_new_location(user, ip_address)
        is_new_device = check_new_device(user, user_agent)
        
        # If no 2FA, login directly
        login_user(user, remember=form.remember_me.data)
        
        # Record successful login attempt
        user.record_login(ip_address, user_agent, successful=True)
        
        # Log security event for successful login
        from app.utils.security import log_security_event
        log_security_event('login_successful', user_id=user.id,
                          details={'ip': ip_address, 
                                  'new_location': is_new_location,
                                  'new_device': is_new_device})
        
        # Create session activity record
        try:
            # Use a random session ID if session.sid is not available 
            import uuid
            session_id = getattr(session, 'sid', str(uuid.uuid4()))
            
            session_activity = SessionActivity(
                user_id=user.id,
                session_id=session_id,
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string
            )
            db.session.add(session_activity)
            db.session.commit()
        except Exception as e:
            logger.error(f"Error creating session activity: {str(e)}")
            # Ensure login still works even if session tracking fails
            db.session.rollback()
        
        logger.info(f"User logged in: {user.username}")
        
        # Redirect to the page the user was trying to access
        next_page = request.args.get('next')
        if not next_page or not next_page.startswith('/'):
            next_page = url_for('user.index')
        
        return redirect(next_page)
    
    return render_template('auth/login.html', title='Sign In', form=form, app_name="NexusSync")

@auth_bp.route('/two-factor', methods=['GET', 'POST'])
def two_factor_auth():
    """Two-factor authentication verification page."""
    if current_user.is_authenticated:
        return redirect(url_for('user.index'))
    
    # Check if we have a user ID in session
    if 'two_factor_user_id' not in session:
        flash('Authentication error. Please try logging in again.', 'danger')
        return redirect(url_for('auth.login'))
    
    form = TwoFactorForm()
    
    if form.validate_on_submit():
        user_id = session['two_factor_user_id']
        user = User.query.get(user_id)
        
        if not user:
            flash('Authentication error. Please try logging in again.', 'danger')
            return redirect(url_for('auth.login'))
        
        # Find the token
        token = TwoFactorToken.query.filter(
            TwoFactorToken.user_id == user.id,
            TwoFactorToken.token == form.token.data,
            TwoFactorToken.is_used == False,
            TwoFactorToken.expires_at > datetime.utcnow()
        ).first()
        
        if not token:
            flash('Invalid or expired verification code. Please try again.', 'danger')
            return redirect(url_for('auth.two_factor_auth'))
        
        # Mark token as used
        token.is_used = True
        
        # Get client info for security tracking
        ip_address = request.remote_addr
        user_agent = request.user_agent.string if request.user_agent else "Unknown"
        
        # Check for login from new location or device
        from app.utils.location import check_new_location, check_new_device
        is_new_location = check_new_location(user, ip_address)
        is_new_device = check_new_device(user, user_agent)
        
        # Login the user
        login_user(user)
        
        # Record successful login attempt
        user.record_login(ip_address, user_agent, successful=True)
        
        # Log security event for successful 2FA login
        from app.utils.security import log_security_event
        log_security_event('2fa_login_successful', user_id=user.id,
                          details={'ip': ip_address, 
                                  'new_location': is_new_location,
                                  'new_device': is_new_device})
        
        # Create session activity record
        try:
            # Use a random session ID if session.sid is not available 
            import uuid
            session_id = getattr(session, 'sid', str(uuid.uuid4()))
            
            session_activity = SessionActivity(
                user_id=user.id,
                session_id=session_id,
                ip_address=request.remote_addr,
                user_agent=request.user_agent.string
            )
            db.session.add(session_activity)
            db.session.commit()
        except Exception as e:
            logger.error(f"Error creating session activity: {str(e)}")
            # Ensure login still works even if session tracking fails
            db.session.rollback()
        
        # Clear the 2FA session data
        session.pop('two_factor_user_id', None)
        
        logger.info(f"User completed 2FA and logged in: {user.username}")
        
        # Redirect to the page the user was trying to access
        next_page = request.args.get('next')
        if not next_page or not next_page.startswith('/'):
            next_page = url_for('user.index')
        
        return redirect(next_page)
    
    return render_template('auth/two_factor.html', title='Two-Factor Authentication', form=form, app_name="NexusSync")

@auth_bp.route('/logout')
def logout():
    """User logout."""
    if current_user.is_authenticated:
        try:
            # Use a random session ID if session.sid is not available 
            import uuid
            session_id = getattr(session, 'sid', str(uuid.uuid4()))
            
            # Mark session as inactive
            session_activity = SessionActivity.query.filter_by(
                user_id=current_user.id,
                session_id=session_id,
                is_active=True
            ).first()
            
            if session_activity:
                session_activity.is_active = False
                db.session.commit()
        except Exception as e:
            logger.error(f"Error updating session activity: {str(e)}")
            # Ensure logout still works even if session tracking fails
            db.session.rollback()
        
        logger.info(f"User logged out: {current_user.username}")
    
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))

@auth_bp.route('/register', methods=['GET', 'POST'])
@auth_bp.route('/register/', methods=['GET', 'POST'])
def register():
    """User registration page."""
    # Apply rate limiting for registration to prevent abuse
    current_app.rate_limits['register']
    
    if current_user.is_authenticated:
        return redirect(url_for('user.index'))
    
    form = RegistrationForm()
    
    if form.validate_on_submit():
        # Get client info for security tracking
        ip_address = request.remote_addr
        user_agent = request.user_agent.string if request.user_agent else "Unknown"
        
        # Validate password complexity
        is_valid, message = User.validate_password_complexity(form.password.data)
        if not is_valid:
            flash(message, 'danger')
            return render_template('auth/register.html', title='Register', form=form, app_name="NexusSync")
        
        # Create the new user
        user = User(
            username=form.username.data,
            email=form.email.data,
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            is_active=True,
            is_email_confirmed=False,
            last_ip=ip_address,
            last_user_agent=user_agent
        )
        user.set_password(form.password.data)
        
        # Add user role
        from app.models.role import Role
        user_role = Role.query.filter_by(name='user').first()
        if user_role:
            user.add_role(user_role)
        
        db.session.add(user)
        db.session.commit()
        
        # Send confirmation email
        send_confirmation_email(user)
        
        # Log the security event
        from app.utils.security import log_security_event
        log_security_event('user_registered', user_id=user.id, 
                          details={'ip': ip_address, 'username': user.username})
        
        logger.info(f"New user registered: {user.username} from IP: {ip_address}")
        flash('Registration successful! Please check your email to confirm your account.', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('auth/register.html', title='Register', form=form, app_name="NexusSync")

@auth_bp.route('/reset-password-request', methods=['GET', 'POST'])
@auth_bp.route('/reset-password-request/', methods=['GET', 'POST'])
def reset_password_request():
    """Password reset request page."""
    # Apply strict rate limiting for password reset to prevent enumeration attacks
    current_app.rate_limits['password_reset']
    
    if current_user.is_authenticated:
        return redirect(url_for('user.index'))
    
    form = PasswordResetRequestForm()
    
    if form.validate_on_submit():
        # Get client info for security tracking
        ip_address = request.remote_addr
        user_agent = request.user_agent.string if request.user_agent else "Unknown"
        
        # Find user by email
        user = User.query.filter_by(email=form.email.data).first()
        
        if user:
            # Generate token with proper expiry
            token = PasswordResetToken.generate_token()
            password_reset = PasswordResetToken(
                user_id=user.id,
                token=token,
                expires_at=datetime.utcnow() + timedelta(hours=24)
            )
            db.session.add(password_reset)
            db.session.commit()
            
            # Send reset email
            send_password_reset_email(user, token)
            
            # Log the security event
            from app.utils.security import log_security_event
            log_security_event('password_reset_requested', user_id=user.id, 
                            details={'ip': ip_address})
            
            logger.info(f"Password reset requested for: {user.email} from IP: {ip_address}")
        else:
            # Log attempted reset for non-existent account (potential account enumeration)
            logger.warning(f"Password reset attempted for non-existent email: {form.email.data} from IP: {ip_address}")
            
            from app.utils.security import log_security_event
            log_security_event('password_reset_invalid_email', 
                            details={'email': form.email.data, 'ip': ip_address})
        
        # Always show the same message even if email not found for security
        # This prevents account enumeration
        flash('Check your email for instructions to reset your password.', 'info')
        
        # Add randomized delay to prevent timing attacks
        import random
        import time
        time.sleep(random.uniform(0.5, 1.5))
        
        return redirect(url_for('auth.login'))
    
    return render_template('auth/reset_password_request.html', 
                        title='Reset Password', 
                        form=form,
                        app_name="NexusSync")

@auth_bp.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Password reset page using token."""
    if current_user.is_authenticated:
        return redirect(url_for('user.index'))
    
    # Find token in database
    reset_token = PasswordResetToken.query.filter(
        PasswordResetToken.token == token,
        PasswordResetToken.is_used == False,
        PasswordResetToken.expires_at > datetime.utcnow()
    ).first()
    
    if not reset_token:
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('auth.login'))
    
    user = User.query.get(reset_token.user_id)
    
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('auth.login'))
    
    form = PasswordResetForm()
    
    if form.validate_on_submit():
        user.set_password(form.password.data)
        
        # Mark token as used
        reset_token.is_used = True
        db.session.commit()
        
        logger.info(f"Password reset completed for: {user.email}")
        flash('Your password has been reset.', 'success')
        return redirect(url_for('auth.login'))
    
    return render_template('auth/reset_password.html', 
                          title='Reset Password', 
                          form=form,
                          app_name="NexusSync")

@auth_bp.route('/confirm-email/<token>')
def confirm_email(token):
    """Confirm user email address using token."""
    if current_user.is_authenticated and current_user.is_email_confirmed:
        return redirect(url_for('user.index'))
    
    # This is a simplified version - in a real app, you'd store email confirmation tokens
    # in the database with expiry times and user associations
    
    # For now, we'll use a very simple token verification
    # In a real app, you'd have a proper token verification system
    from itsdangerous import URLSafeTimedSerializer
    from flask import current_app
    
    s = URLSafeTimedSerializer(current_app.config['SECRET_KEY'])
    try:
        email = s.loads(token, max_age=3600)  # Token valid for 1 hour
    except:
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('user.index'))
    
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('User not found.', 'danger')
        return redirect(url_for('user.index'))
    
    if user.is_email_confirmed:
        flash('Your email is already confirmed.', 'info')
    else:
        user.is_email_confirmed = True
        db.session.commit()
        logger.info(f"Email confirmed for: {user.email}")
        flash('Thank you for confirming your email!', 'success')
    
    # If the user is not logged in, redirect to login
    if not current_user.is_authenticated:
        return redirect(url_for('auth.login'))
    
    return redirect(url_for('user.index'))