import os
import logging
from datetime import datetime, timedelta
from flask import Blueprint, flash, redirect, render_template, request, url_for, jsonify, session, current_app, g
from flask_login import login_user, logout_user, current_user, login_required
from flask_mail import Message
from sqlalchemy import desc
from werkzeug.security import generate_password_hash
from models import User, Notification, PasswordResetToken, TwoFactorToken, Role, SessionActivity
from forms import LoginForm, RegistrationForm, EditProfileForm, PasswordResetRequestForm, PasswordResetForm, TwoFactorForm
from app import db, mail, limiter, login_manager
from cookies import set_session_cookie, clear_session_cookie, validate_session_cookie
# ElasticSearch functionality has been removed

logger = logging.getLogger(__name__)

user_bp = Blueprint('user', __name__, url_prefix='')

@user_bp.before_request
def before_request():
    if current_user.is_authenticated:
        # Check for session validity
        is_valid_session = validate_session_cookie(current_user)
        if not is_valid_session:
            logout_user()
            clear_session_cookie()
            flash('Your session has expired or your credentials have changed. Please log in again.', 'warning')
            return redirect(url_for('user.login'))

@user_bp.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.is_admin():
            return redirect(url_for('admin.index'))
        return render_template('user_index.html', title='Home')
    return redirect(url_for('user.login'))

@user_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if current_user.is_authenticated:
        return redirect(url_for('user.index'))
    
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password', 'danger')
            return render_template('login.html', title='Sign In', form=form)
        
        if not user.is_active:
            flash('This account has been deactivated. Please contact an administrator.', 'danger')
            return render_template('login.html', title='Sign In', form=form)
        
        if user.two_factor_enabled:
            # Generate and store 2FA token
            token = TwoFactorToken.generate_token()
            two_factor = TwoFactorToken(
                user_id=user.id,
                token=token,
                expires_at=datetime.utcnow() + timedelta(minutes=10)
            )
            db.session.add(two_factor)
            db.session.commit()
            
            # Send token via email (in a real app, you might use SMS or authenticator app)
            send_two_factor_token(user.email, token)
            
            session['two_factor_user_id'] = user.id
            return redirect(url_for('user.two_factor_auth'))
        
        # Regular login
        login_user(user, remember=form.remember_me.data)
        user.last_login = datetime.utcnow()
        user.last_ip = request.remote_addr
        user.last_user_agent = request.user_agent.string
        
        # Generate a unique session ID if not exists
        if 'session_id' not in session:
            session['session_id'] = os.urandom(16).hex()
        
        # Record session activity
        session_activity = SessionActivity(
            user_id=user.id,
            session_id=session.get("session_id", os.urandom(16).hex()),
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string
        )
        db.session.add(session_activity)
        db.session.commit()
        
        # Set secure session cookie
        set_session_cookie(user)
        
        next_page = request.args.get('next')
        if not next_page or not next_page.startswith('/'):
            next_page = url_for('user.index')
            
        flash('Login successful!', 'success')
        return redirect(next_page)
    
    return render_template('login.html', title='Sign In', form=form)

@user_bp.route('/two-factor', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def two_factor_auth():
    if 'two_factor_user_id' not in session:
        return redirect(url_for('user.login'))
    
    form = TwoFactorForm()
    if form.validate_on_submit():
        user_id = session['two_factor_user_id']
        user = User.query.get(user_id)
        
        if not user:
            flash('Authentication error. Please try logging in again.', 'danger')
            return redirect(url_for('user.login'))
        
        # Verify token
        token = TwoFactorToken.query.filter_by(
            user_id=user_id,
            token=form.token.data,
            is_used=False
        ).order_by(desc(TwoFactorToken.created_at)).first()
        
        if not token or token.expires_at < datetime.utcnow():
            flash('Invalid or expired security code. Please try again.', 'danger')
            return render_template('two_factor.html', title='Two-Factor Authentication', form=form)
        
        # Mark token as used
        token.is_used = True
        db.session.commit()
        
        # Complete login
        login_user(user)
        user.last_login = datetime.utcnow()
        user.last_ip = request.remote_addr
        user.last_user_agent = request.user_agent.string
        
        # Record session activity
        session_activity = SessionActivity(
            user_id=user.id,
            session_id=session.get("session_id", os.urandom(16).hex()),
            ip_address=request.remote_addr,
            user_agent=request.user_agent.string
        )
        db.session.add(session_activity)
        db.session.commit()
        
        # Set secure session cookie
        set_session_cookie(user)
        
        # Clean up session
        session.pop('two_factor_user_id', None)
        
        next_page = request.args.get('next')
        if not next_page or not next_page.startswith('/'):
            next_page = url_for('user.index')
            
        flash('Login successful!', 'success')
        return redirect(next_page)
    
    return render_template('two_factor.html', title='Two-Factor Authentication', form=form)

@user_bp.route('/logout')
def logout():
    if current_user.is_authenticated:
        # Update session activity record
        session_activity = SessionActivity.query.filter_by(
            user_id=current_user.id,
            session_id=session.get("session_id", os.urandom(16).hex()),
            is_active=True
        ).first()
        
        if session_activity:
            session_activity.is_active = False
            session_activity.last_activity = datetime.utcnow()
            db.session.commit()
    
    logout_user()
    clear_session_cookie()
    flash('You have been logged out.', 'info')
    return redirect(url_for('user.login'))

@user_bp.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    if current_user.is_authenticated:
        return redirect(url_for('user.index'))
    
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            is_active=True,
            is_email_confirmed=False
        )
        user.set_password(form.password.data)
        
        # Assign default user role
        user_role = Role.query.filter_by(name='user').first()
        user.roles.append(user_role)
        
        db.session.add(user)
        db.session.commit()
        
        # Elasticsearch removed
        logger.debug(f"User {user.username} created")
        
        # Send confirmation email
        send_confirmation_email(user)
        
        flash('Registration successful! Please check your email to confirm your account.', 'success')
        return redirect(url_for('user.login'))
    
    return render_template('registration.html', title='Register', form=form)

@user_bp.route('/profile')
@login_required
def profile():
    return render_template('profile.html', title='Profile', user=current_user)

@user_bp.route('/edit_profile', methods=['GET', 'POST'])
@login_required
def edit_profile():
    form = EditProfileForm(original_username=current_user.username, original_email=current_user.email)
    
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        current_user.first_name = form.first_name.data
        current_user.last_name = form.last_name.data
        
        db.session.commit()
        
        # Elasticsearch removed
        logger.debug(f"User profile updated: {current_user.username}")
        
        flash('Your profile has been updated.', 'success')
        return redirect(url_for('user.profile'))
    
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
        form.first_name.data = current_user.first_name
        form.last_name.data = current_user.last_name
    
    return render_template('edit_profile.html', title='Edit Profile', form=form)

@user_bp.route('/reset_password_request', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def reset_password_request():
    if current_user.is_authenticated:
        return redirect(url_for('user.index'))
    
    form = PasswordResetRequestForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            # Generate reset token
            token = PasswordResetToken.generate_token()
            reset_token = PasswordResetToken(
                user_id=user.id,
                token=token,
                expires_at=datetime.utcnow() + timedelta(hours=24)
            )
            db.session.add(reset_token)
            db.session.commit()
            
            # Send reset email
            send_password_reset_email(user, token)
        
        # To prevent email enumeration, always show success message
        flash('If your email exists in our system, you will receive password reset instructions.', 'info')
        return redirect(url_for('user.login'))
    
    return render_template('password_reset_request.html', title='Reset Password', form=form)

@user_bp.route('/reset_password/<token>', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def reset_password(token):
    if current_user.is_authenticated:
        return redirect(url_for('user.index'))
    
    # Verify token
    reset_token = PasswordResetToken.query.filter_by(token=token, is_used=False).first()
    if not reset_token or reset_token.expires_at < datetime.utcnow():
        flash('The password reset link is invalid or has expired.', 'danger')
        return redirect(url_for('user.reset_password_request'))
    
    form = PasswordResetForm()
    if form.validate_on_submit():
        user = User.query.get(reset_token.user_id)
        user.set_password(form.password.data)
        
        # Mark token as used
        reset_token.is_used = True
        db.session.commit()
        
        flash('Your password has been reset. You can now log in with your new password.', 'success')
        return redirect(url_for('user.login'))
    
    return render_template('password_reset.html', title='Reset Password', form=form)

@user_bp.route('/notifications')
@login_required
def notifications():
    return render_template('notifications.html', title='Notifications')

@user_bp.route('/api/notifications')
@login_required
def get_notifications():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    notifications = Notification.query.filter_by(
        user_id=current_user.id
    ).order_by(desc(Notification.created_at)).paginate(page=page, per_page=per_page)
    
    return jsonify({
        'notifications': [n.to_dict() for n in notifications.items],
        'total': notifications.total,
        'pages': notifications.pages,
        'page': page
    })

@user_bp.route('/api/notifications/mark_read/<int:notification_id>', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    notification = Notification.query.filter_by(id=notification_id, user_id=current_user.id).first_or_404()
    notification.is_read = True
    db.session.commit()
    
    return jsonify({'success': True})

@user_bp.route('/api/notifications/dismiss/<int:notification_id>', methods=['POST'])
@login_required
def dismiss_notification(notification_id):
    notification = Notification.query.filter_by(id=notification_id, user_id=current_user.id).first_or_404()
    notification.is_dismissed = True
    db.session.commit()
    
    return jsonify({'success': True})

@user_bp.route('/messages')
@login_required
def messages():
    """View messages and conversations."""
    # Redirect to the new static messages page
    return redirect(url_for('user.messages_static'))

@user_bp.route('/messages/static')
@user_bp.route('/messages/static/<conversation_id>')
@login_required
def messages_static(conversation_id=None):
    """Static version of the messages page that doesn't rely on JavaScript."""
    return render_template('messages_static.html', 
                          title='Messages',
                          conversation_id=conversation_id)

@user_bp.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    """User settings page with profile, security, and notification settings"""
    form = EditProfileForm(current_user.username, current_user.email)
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        current_user.first_name = form.first_name.data
        current_user.last_name = form.last_name.data
        db.session.commit()
        flash('Your profile has been updated.', 'success')
        return redirect(url_for('user.settings', _anchor='profile'))
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
        form.first_name.data = current_user.first_name
        form.last_name.data = current_user.last_name
    
    return render_template('settings.html', title='Account Settings', form=form)

@user_bp.route('/settings/resend-confirmation', methods=['POST'])
@login_required
def resend_confirmation():
    """Resend email confirmation link"""
    if current_user.is_email_confirmed:
        flash('Your email is already confirmed.', 'info')
        return redirect(url_for('user.settings', _anchor='security'))
    
    # Send confirmation email
    send_confirmation_email(current_user)
    
    flash('A new confirmation email has been sent. Please check your inbox.', 'success')
    return redirect(url_for('user.settings', _anchor='security'))

@user_bp.route('/settings/setup-two-factor', methods=['GET', 'POST'])
@login_required
def setup_two_factor():
    """Set up two-factor authentication"""
    if current_user.two_factor_enabled:
        flash('Two-factor authentication is already enabled.', 'info')
        return redirect(url_for('user.settings', _anchor='security'))
    
    # Generate and send a token for verification
    token = TwoFactorToken.generate_token()
    two_factor_token = TwoFactorToken(
        user_id=current_user.id,
        token=token,
        expires_at=datetime.utcnow() + timedelta(minutes=10)
    )
    db.session.add(two_factor_token)
    db.session.commit()
    
    # Send the token via email
    send_two_factor_token(current_user.email, token)
    
    form = TwoFactorForm()
    if form.validate_on_submit():
        # Verify the token
        valid_token = TwoFactorToken.query.filter_by(
            user_id=current_user.id,
            token=form.token.data,
            is_used=False
        ).first()
        
        if not valid_token or valid_token.expires_at < datetime.utcnow():
            flash('Invalid or expired verification code. Please try again.', 'danger')
            return redirect(url_for('user.setup_two_factor'))
        
        # Enable 2FA for the user
        current_user.two_factor_enabled = True
        
        # Mark token as used
        valid_token.is_used = True
        db.session.commit()
        
        flash('Two-factor authentication has been enabled for your account.', 'success')
        return redirect(url_for('user.settings', _anchor='security'))
    
    return render_template('setup_two_factor.html', title='Enable Two-Factor Authentication', form=form)

@user_bp.route('/settings/disable-two-factor', methods=['POST'])
@login_required
def disable_two_factor():
    """Disable two-factor authentication"""
    if not current_user.two_factor_enabled:
        flash('Two-factor authentication is not enabled.', 'info')
        return redirect(url_for('user.settings', _anchor='security'))
    
    current_user.two_factor_enabled = False
    db.session.commit()
    
    # Add notification for the user
    notification = Notification(
        user_id=current_user.id,
        title='Two-Factor Authentication Disabled',
        message='Two-factor authentication has been disabled for your account. If you did not make this change, please contact support immediately.'
    )
    db.session.add(notification)
    db.session.commit()
    
    flash('Two-factor authentication has been disabled for your account.', 'success')
    return redirect(url_for('user.settings', _anchor='security'))

@user_bp.route('/settings/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Change user password"""
    form = PasswordResetForm()
    if form.validate_on_submit():
        current_user.set_password(form.password.data)
        db.session.commit()
        
        # Add notification for the user
        notification = Notification(
            user_id=current_user.id,
            title='Password Changed',
            message='Your password has been successfully changed. If you did not make this change, please contact support immediately.'
        )
        db.session.add(notification)
        db.session.commit()
        
        flash('Your password has been changed.', 'success')
        return redirect(url_for('user.settings', _anchor='security'))
    
    return render_template('change_password.html', title='Change Password', form=form)

@user_bp.route('/security/two-factor')
@login_required
def two_factor_settings():
    """Configure two-factor authentication - redirects to settings page."""
    return redirect(url_for('user.settings', _anchor='security'))

# Global search API endpoint
@user_bp.route('/api/global-search', methods=['GET'])
@login_required
def global_search():
    """API endpoint for global search across users, pages, and settings"""
    query = request.args.get('q', '').strip().lower()
    if not query or len(query) < 2:
        return jsonify({'results': []})
    
    results = []
    
    # 1. Search navigation items
    nav_items = [
        {'title': 'Dashboard', 'url': url_for('user.index'), 'icon': 'home', 'category': 'Page', 
         'description': 'Main dashboard with overview and statistics', 'keywords': 'dashboard home main overview'},
        {'title': 'Profile', 'url': url_for('user.profile'), 'icon': 'user', 'category': 'Page', 
         'description': 'View and manage your profile information', 'keywords': 'profile account user information personal'},
        {'title': 'Edit Profile', 'url': url_for('user.edit_profile'), 'icon': 'edit', 'category': 'Page', 
         'description': 'Edit your profile information', 'keywords': 'edit profile account settings user information update'},
        {'title': 'Messages', 'url': url_for('user.messages'), 'icon': 'message-square', 'category': 'Page', 
         'description': 'View your messages and conversations', 'keywords': 'messages inbox chat communication'},
        {'title': 'Notifications', 'url': url_for('user.notifications'), 'icon': 'bell', 'category': 'Page', 
         'description': 'View your notifications', 'keywords': 'notifications alerts updates messages'},
        {'title': 'Security Settings', 'url': url_for('user.two_factor_settings'), 'icon': 'shield', 'category': 'Settings', 
         'description': 'Manage two-factor authentication', 'keywords': 'security 2fa two factor authentication settings'},
        {'title': 'Password Reset', 'url': url_for('user.reset_password_request'), 'icon': 'key', 'category': 'Settings', 
         'description': 'Request a password reset', 'keywords': 'password reset security forgot change'}
    ]
    
    # If user is admin, add admin pages
    if current_user.is_admin():
        admin_items = [
            {'title': 'Admin Dashboard', 'url': url_for('admin.index'), 'icon': 'sliders', 'category': 'Admin', 
             'description': 'Administrative dashboard and overview', 'keywords': 'admin dashboard control panel'},
            {'title': 'User Management', 'url': url_for('admin.list_users'), 'icon': 'users', 'category': 'Admin', 
             'description': 'Manage users and permissions', 'keywords': 'admin users management permissions roles'},
            {'title': 'Active Sessions', 'url': url_for('admin.active_sessions'), 'icon': 'activity', 'category': 'Admin', 
             'description': 'View and manage active user sessions', 'keywords': 'admin sessions active users online'},
            {'title': 'Create Notification', 'url': url_for('admin.create_notification'), 'icon': 'send', 'category': 'Admin', 
             'description': 'Create and send notifications to users', 'keywords': 'admin notifications send message alert'}
        ]
        nav_items.extend(admin_items)
    
    # Filter navigation items based on query
    for item in nav_items:
        if (query in item['title'].lower() or 
            query in item['description'].lower() or 
            query in item.get('keywords', '').lower()):
            results.append(item)
    
    # 2. Search users (if admin or searching for self)
    try:
        if current_user.is_admin():
            # Admins can search all users
            user_query = User.query.filter(
                db.or_(
                    db.func.lower(User.username).contains(query),
                    db.func.lower(User.email).contains(query),
                    db.func.lower(User.first_name).contains(query),
                    db.func.lower(User.last_name).contains(query)
                )
            ).limit(5).all()
            
            for user in user_query:
                user_result = {
                    'title': user.username,
                    'description': f"{user.first_name} {user.last_name}" if user.first_name and user.last_name else user.email,
                    'url': url_for('admin.edit_user', user_id=user.id),
                    'icon': 'user',
                    'category': 'User'
                }
                results.append(user_result)
        else:
            # Regular users can only find themselves in search
            if (query in current_user.username.lower() or 
                (current_user.email and query in current_user.email.lower()) or
                (current_user.first_name and query in current_user.first_name.lower()) or
                (current_user.last_name and query in current_user.last_name.lower())):
                user_result = {
                    'title': current_user.username,
                    'description': 'Your profile',
                    'url': url_for('user.profile'),
                    'icon': 'user',
                    'category': 'User'
                }
                results.append(user_result)
    except Exception as e:
        logger.error(f"Error searching users: {e}")
    
    # Sort results by relevance: title match first, then category
    def sort_key(item):
        title_match = 1 if query in item['title'].lower() else 0
        # Order by category: Page, Settings, User, Admin
        category_order = {'Page': 0, 'Settings': 1, 'User': 2, 'Admin': 3}
        return (-title_match, category_order.get(item.get('category', ''), 99))
    
    results.sort(key=sort_key)
    
    # Limit to 10 results
    results = results[:10]
    
    return jsonify({'results': results})

@user_bp.route('/search')
@login_required
def search():
    q = request.args.get('q', '')
    if not q:
        return jsonify({'results': []})
    
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        
        # Use SQLAlchemy search instead of ElasticSearch
        query = q.lower()
        search_query = User.query.filter(
            db.or_(
                db.func.lower(User.username).contains(query),
                db.func.lower(User.email).contains(query),
                db.func.lower(User.first_name).contains(query),
                db.func.lower(User.last_name).contains(query)
            )
        )
        
        # Get total count for pagination
        total = search_query.count()
        
        # Apply pagination
        users = search_query.paginate(page=page, per_page=per_page, error_out=False).items
            
        results = [{
            'id': user.id,
            'username': user.username,
            'name': f"{user.first_name} {user.last_name}" if user.first_name and user.last_name else user.username
        } for user in users]
        
        return jsonify({
            'results': results,
            'total': total,
            'page': page,
            'per_page': per_page
        })
    except Exception as e:
        logger.error(f"Search error: {e}")
        return jsonify({
            'results': [],
            'error': 'Search functionality encountered an error'
        })

# Helper functions
def send_confirmation_email(user):
    """Send account confirmation email."""
    try:
        token = PasswordResetToken.generate_token()
        reset_token = PasswordResetToken(
            user_id=user.id,
            token=token,
            expires_at=datetime.utcnow() + timedelta(days=7)
        )
        db.session.add(reset_token)
        db.session.commit()
        
        confirm_url = url_for('user.confirm_email', token=token, _external=True)
        
        msg = Message('Confirm Your Account',
                     recipients=[user.email])
        msg.html = f'''
        <p>Welcome to our application!</p>
        <p>Please click on the following link to confirm your account:</p>
        <p><a href="{confirm_url}">{confirm_url}</a></p>
        <p>If you did not register for an account, please ignore this email.</p>
        '''
        
        mail.send(msg)
        logger.info(f"Confirmation email sent to {user.email}")
    except Exception as e:
        logger.error(f"Failed to send confirmation email: {e}")
        db.session.rollback()

def send_password_reset_email(user, token):
    """Send password reset email."""
    try:
        reset_url = url_for('user.reset_password', token=token, _external=True)
        
        msg = Message('Password Reset Request',
                     recipients=[user.email])
        msg.html = f'''
        <p>You requested a password reset for your account.</p>
        <p>Please click on the following link to reset your password:</p>
        <p><a href="{reset_url}">{reset_url}</a></p>
        <p>If you did not request a password reset, please ignore this email.</p>
        <p>This link will expire in 24 hours.</p>
        '''
        
        mail.send(msg)
        logger.info(f"Password reset email sent to {user.email}")
    except Exception as e:
        logger.error(f"Failed to send password reset email: {e}")
        db.session.rollback()

def send_two_factor_token(email, token):
    """Send two-factor authentication token via email."""
    try:
        msg = Message('Your Authentication Code',
                     recipients=[email])
        msg.html = f'''
        <p>Your authentication code is: <strong>{token}</strong></p>
        <p>This code will expire in 10 minutes.</p>
        <p>If you did not request this code, please ignore this email and secure your account.</p>
        '''
        
        mail.send(msg)
        logger.info(f"Two-factor token sent to {email}")
    except Exception as e:
        logger.error(f"Failed to send two-factor token: {e}")
        db.session.rollback()

@user_bp.route('/confirm_email/<token>')
def confirm_email(token):
    """Confirm user email address."""
    if current_user.is_authenticated and current_user.is_email_confirmed:
        return redirect(url_for('user.index'))
    
    # Verify token
    reset_token = PasswordResetToken.query.filter_by(token=token, is_used=False).first()
    if not reset_token or reset_token.expires_at < datetime.utcnow():
        flash('The confirmation link is invalid or has expired.', 'danger')
        return redirect(url_for('user.login'))
    
    user = User.query.get(reset_token.user_id)
    user.is_email_confirmed = True
    
    # Mark token as used
    reset_token.is_used = True
    db.session.commit()
    
    flash('Your email has been confirmed. You can now log in.', 'success')
    return redirect(url_for('user.login'))

# API Routes for AJAX requests
@user_bp.route('/api/notifications')
@login_required
def api_get_notifications():
    """API endpoint to get notifications"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 10, type=int)
    
    query = current_user.notifications.filter_by(is_dismissed=False).order_by(Notification.created_at.desc())
    pagination = query.paginate(page=page, per_page=per_page, error_out=False)
    
    notifications = [{
        'id': n.id,
        'title': n.title,
        'message': n.message,
        'is_read': n.is_read,
        'created_at': n.created_at.isoformat()
    } for n in pagination.items]
    
    return jsonify({
        'notifications': notifications,
        'total': pagination.total,
        'pages': pagination.pages,
        'current_page': page
    })

@user_bp.route('/api/notifications/<int:notification_id>/read', methods=['POST'])
@login_required
def api_mark_notification_read(notification_id):
    """API endpoint to mark a notification as read"""
    notification = Notification.query.get_or_404(notification_id)
    
    if notification.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    notification.is_read = True
    db.session.commit()
    
    return jsonify({'success': True})

@user_bp.route('/api/notifications/<int:notification_id>/dismiss', methods=['POST'])
@login_required
def api_dismiss_notification(notification_id):
    """API endpoint to dismiss a notification"""
    notification = Notification.query.get_or_404(notification_id)
    
    if notification.user_id != current_user.id:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    notification.is_dismissed = True
    db.session.commit()
    
    return jsonify({'success': True})
