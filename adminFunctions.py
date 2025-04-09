import logging
from datetime import datetime
from flask import Blueprint, flash, redirect, render_template, request, url_for, jsonify, abort
from flask_login import current_user, login_required
from sqlalchemy import desc
from models import User, Role, Notification, SessionActivity
from forms import AdminUserForm
from app import db, limiter
from elasticSearch import add_to_index, remove_from_index, query_index

logger = logging.getLogger(__name__)

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.before_request
def check_admin():
    if not current_user.is_authenticated:
        abort(401)  # Unauthorized
    if not current_user.is_admin():
        abort(403)  # Forbidden

@admin_bp.route('/')
@login_required
def index():
    users_count = User.query.count()
    active_sessions = SessionActivity.query.filter_by(is_active=True).count()
    
    # Get 5 most recently registered users
    recent_users = User.query.order_by(desc(User.created_at)).limit(5).all()
    
    return render_template('admin_index.html', 
                           title='Admin Dashboard',
                           users_count=users_count,
                           active_sessions=active_sessions,
                           recent_users=recent_users)

@admin_bp.route('/users')
@login_required
def list_users():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    users = User.query.order_by(User.username).paginate(page=page, per_page=per_page)
    
    return render_template('admin_users.html', 
                           title='User Management',
                           users=users)

@admin_bp.route('/users/<int:user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # Don't allow admins to edit themselves through this interface
    if user.id == current_user.id:
        flash('You cannot edit your own account through this interface.', 'warning')
        return redirect(url_for('admin.list_users'))
    
    form = AdminUserForm()
    
    if form.validate_on_submit():
        user.username = form.username.data
        user.email = form.email.data
        user.first_name = form.first_name.data
        user.last_name = form.last_name.data
        user.is_active = form.is_active.data
        user.is_email_confirmed = form.is_email_confirmed.data
        user.two_factor_enabled = form.two_factor_enabled.data
        
        # Update roles
        admin_role = Role.query.filter_by(name='admin').first()
        user_role = Role.query.filter_by(name='user').first()
        
        # Clear existing roles
        user.roles = []
        
        # Add selected role
        if form.roles.data == 'admin':
            user.roles.append(admin_role)
            user.roles.append(user_role)  # Admins also have user privileges
        else:
            user.roles.append(user_role)
        
        db.session.commit()
        
        # Update search index if Elasticsearch is available
        try:
            add_to_index('users', user)
        except Exception as e:
            logger.warning(f"Failed to update user in search index: {e}")
        
        flash(f'User {user.username} has been updated.', 'success')
        return redirect(url_for('admin.list_users'))
    
    elif request.method == 'GET':
        form.username.data = user.username
        form.email.data = user.email
        form.first_name.data = user.first_name
        form.last_name.data = user.last_name
        form.is_active.data = user.is_active
        form.is_email_confirmed.data = user.is_email_confirmed
        form.two_factor_enabled.data = user.two_factor_enabled
        
        if user.is_admin():
            form.roles.data = 'admin'
        else:
            form.roles.data = 'user'
    
    return render_template('admin_edit_user.html', 
                           title='Edit User',
                           form=form,
                           user=user)

@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
def delete_user(user_id):
    user = User.query.get_or_404(user_id)
    
    # Don't allow admins to delete themselves
    if user.id == current_user.id:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('admin.list_users'))
    
    username = user.username
    
    # Remove from search index if Elasticsearch is available
    try:
        remove_from_index('users', user)
    except Exception as e:
        logger.warning(f"Failed to remove user from search index: {e}")
    
    # Delete user and all associated data
    db.session.delete(user)
    db.session.commit()
    
    flash(f'User {username} has been deleted.', 'success')
    return redirect(url_for('admin.list_users'))

@admin_bp.route('/users/<int:user_id>/reset_password', methods=['POST'])
@login_required
@limiter.limit("10 per minute")
def reset_user_password(user_id):
    user = User.query.get_or_404(user_id)
    
    # Generate random password
    import secrets
    import string
    password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(12))
    
    # Update user password
    user.set_password(password)
    db.session.commit()
    
    # Add notification for user
    notification = Notification(
        user_id=user.id,
        title='Password Reset by Administrator',
        message=f'Your password has been reset by an administrator. Your new temporary password is: {password}'
    )
    db.session.add(notification)
    db.session.commit()
    
    flash(f'Password for {user.username} has been reset. Temporary password: {password}', 'success')
    return redirect(url_for('admin.edit_user', user_id=user.id))

@admin_bp.route('/sessions')
@login_required
def active_sessions():
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    sessions = SessionActivity.query.filter_by(is_active=True).order_by(
        desc(SessionActivity.last_activity)).paginate(page=page, per_page=per_page)
    
    return render_template('admin_sessions.html', 
                           title='Active Sessions',
                           sessions=sessions)

@admin_bp.route('/sessions/terminate/<int:session_id>', methods=['POST'])
@login_required
def terminate_session(session_id):
    session = SessionActivity.query.get_or_404(session_id)
    
    session.is_active = False
    session.last_activity = datetime.utcnow()
    db.session.commit()
    
    # Add notification for user
    notification = Notification(
        user_id=session.user_id,
        title='Session Terminated by Administrator',
        message='One of your sessions was terminated by an administrator for security reasons.'
    )
    db.session.add(notification)
    db.session.commit()
    
    flash('Session has been terminated.', 'success')
    return redirect(url_for('admin.active_sessions'))

@admin_bp.route('/search')
@login_required
def search():
    q = request.args.get('q', '')
    if not q:
        return jsonify({'results': []})
    
    try:
        results = query_index('users', q)
        return jsonify({
            'results': results
        })
    except Exception as e:
        logger.error(f"Search error: {e}")
        return jsonify({
            'results': [],
            'error': 'Search functionality is currently unavailable'
        })

@admin_bp.route('/create_notification', methods=['GET', 'POST'])
@login_required
def create_notification():
    if request.method == 'POST':
        title = request.form.get('title')
        message = request.form.get('message')
        user_id = request.form.get('user_id')
        all_users = request.form.get('all_users') == 'on'
        
        if not title or not message:
            flash('Title and message are required.', 'danger')
            return redirect(url_for('admin.create_notification'))
        
        if all_users:
            # Create notification for all users
            users = User.query.all()
            for user in users:
                notification = Notification(
                    user_id=user.id,
                    title=title,
                    message=message
                )
                db.session.add(notification)
            
            db.session.commit()
            flash('Notification sent to all users.', 'success')
        elif user_id:
            # Create notification for specific user
            user = User.query.get(user_id)
            if not user:
                flash('User not found.', 'danger')
                return redirect(url_for('admin.create_notification'))
            
            notification = Notification(
                user_id=user.id,
                title=title,
                message=message
            )
            db.session.add(notification)
            db.session.commit()
            
            flash(f'Notification sent to {user.username}.', 'success')
        else:
            flash('Please select a user or choose to notify all users.', 'danger')
            return redirect(url_for('admin.create_notification'))
        
        return redirect(url_for('admin.index'))
    
    users = User.query.order_by(User.username).all()
    return render_template('admin_create_notification.html', 
                           title='Create Notification',
                           users=users)
