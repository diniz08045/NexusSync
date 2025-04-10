import logging
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from app import db
from app.models.user import User
from app.models.role import Role
from app.models.session import SessionActivity
from app.models.notification import Notification
from app.admin.forms import AdminUserForm, CreateUserForm
from app.utils.decorators import admin_required

# Set up logger
logger = logging.getLogger(__name__)

# Create blueprint
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

def check_admin():
    """Check if the current user is an admin."""
    if not current_user.is_authenticated or not current_user.is_admin():
        logger.warning(f"Unauthorized access attempt to admin page by {current_user.username if current_user.is_authenticated else 'unauthenticated user'}")
        flash('You do not have permission to access this page.', 'danger')
        return False
    return True

@admin_bp.before_request
def before_request():
    """Run before each request in admin blueprint."""
    if not current_user.is_authenticated or not current_user.is_admin():
        flash('You do not have permission to access this page.', 'danger')
        return redirect(url_for('user.index'))

@admin_bp.route('/')
@admin_bp.route('/index')
@login_required
@admin_required
def index():
    """Admin dashboard/home page."""
    user_count = User.query.count()
    active_user_count = User.query.filter_by(is_active=True).count()
    active_sessions_count = SessionActivity.query.filter_by(is_active=True).count()
    notification_count = Notification.query.count()
    
    return render_template('admin/index.html', 
                          title='Admin Dashboard',
                          user_count=user_count, 
                          active_user_count=active_user_count,
                          active_sessions_count=active_sessions_count,
                          notification_count=notification_count,
                          app_name="NexusSync")

@admin_bp.route('/users')
@login_required
@admin_required
def list_users():
    """List all users."""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    users = User.query.paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('admin/list_users.html', 
                          title='User Management',
                          users=users,
                          app_name="NexusSync")

@admin_bp.route('/users/<int:user_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def edit_user(user_id):
    """Edit a user's information."""
    user = User.query.get_or_404(user_id)
    form = AdminUserForm()
    
    # Populate roles choices
    roles = Role.query.all()
    form.roles.choices = [(role.name, role.name.capitalize()) for role in roles]
    
    if form.validate_on_submit():
        user.username = form.username.data
        user.email = form.email.data
        user.first_name = form.first_name.data
        user.last_name = form.last_name.data
        user.is_active = form.is_active.data
        user.is_email_confirmed = form.is_email_confirmed.data
        user.two_factor_enabled = form.two_factor_enabled.data
        
        # Update roles
        for role in roles:
            if role.name == form.roles.data:
                if not user.has_role(role.name):
                    user.add_role(role)
            else:
                if user.has_role(role.name):
                    user.remove_role(role)
        
        db.session.commit()
        logger.info(f"Admin {current_user.username} updated user {user.username}")
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
        
        # Set role select field
        for role in user.roles:
            form.roles.data = role.name
            break
    
    return render_template('admin/edit_user.html', 
                          title='Edit User',
                          form=form,
                          user=user,
                          app_name="NexusSync")

@admin_bp.route('/users/create', methods=['GET', 'POST'])
@login_required
@admin_required
def create_user():
    """Create a new user (admin feature)."""
    form = CreateUserForm()
    
    # Populate roles choices
    roles = Role.query.all()
    form.roles.choices = [(role.name, role.name.capitalize()) for role in roles]
    
    if form.validate_on_submit():
        user = User(
            username=form.username.data,
            email=form.email.data,
            first_name=form.first_name.data,
            last_name=form.last_name.data,
            is_active=form.is_active.data,
            is_email_confirmed=form.is_email_confirmed.data,
            two_factor_enabled=form.two_factor_enabled.data
        )
        user.set_password(form.password.data)
        
        # Add role
        selected_role = Role.query.filter_by(name=form.roles.data).first()
        if selected_role:
            user.add_role(selected_role)
        
        db.session.add(user)
        db.session.commit()
        
        logger.info(f"Admin {current_user.username} created new user {user.username}")
        flash(f'User {user.username} has been created.', 'success')
        return redirect(url_for('admin.list_users'))
    
    return render_template('admin/create_user.html', 
                          title='Create User',
                          form=form,
                          app_name="NexusSync")

@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_user(user_id):
    """Delete a user."""
    user = User.query.get_or_404(user_id)
    
    if user.id == current_user.id:
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('admin.list_users'))
    
    username = user.username
    db.session.delete(user)
    db.session.commit()
    
    logger.info(f"Admin {current_user.username} deleted user {username}")
    flash(f'User {username} has been deleted.', 'success')
    return redirect(url_for('admin.list_users'))

@admin_bp.route('/users/<int:user_id>/reset_password', methods=['POST'])
@login_required
@admin_required
def reset_user_password(user_id):
    """Reset a user's password to a default value."""
    user = User.query.get_or_404(user_id)
    
    # Set a default password
    default_password = 'ChangeMe123!'
    user.set_password(default_password)
    db.session.commit()
    
    logger.info(f"Admin {current_user.username} reset password for user {user.username}")
    flash(f'Password for {user.username} has been reset to {default_password}. Please instruct the user to change it immediately.', 'success')
    return redirect(url_for('admin.edit_user', user_id=user.id))

@admin_bp.route('/sessions')
@login_required
@admin_required
def active_sessions():
    """Show active user sessions."""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    sessions = SessionActivity.query.filter_by(is_active=True).order_by(
        SessionActivity.last_activity.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('admin/active_sessions.html', 
                          title='Active Sessions',
                          sessions=sessions,
                          app_name="NexusSync")

@admin_bp.route('/sessions/<session_id>/terminate', methods=['POST'])
@login_required
@admin_required
def terminate_session(session_id):
    """Terminate a user session."""
    session = SessionActivity.query.filter_by(session_id=session_id, is_active=True).first_or_404()
    
    # Mark as inactive
    session.is_active = False
    db.session.commit()
    
    logger.info(f"Admin {current_user.username} terminated session {session_id} for user {session.user.username}")
    flash(f'Session for {session.user.username} has been terminated.', 'success')
    return redirect(url_for('admin.active_sessions'))

@admin_bp.route('/search')
@login_required
@admin_required
def search():
    """Search users."""
    query = request.args.get('q', '')
    
    if not query:
        return redirect(url_for('admin.list_users'))
    
    users = User.query.filter(
        (User.username.ilike(f'%{query}%')) | 
        (User.email.ilike(f'%{query}%')) |
        (User.first_name.ilike(f'%{query}%')) |
        (User.last_name.ilike(f'%{query}%'))
    ).all()
    
    return render_template('admin/search_results.html', 
                          title=f'Search Results for "{query}"',
                          users=users,
                          query=query,
                          app_name="NexusSync")

@admin_bp.route('/create_notification', methods=['GET', 'POST'])
@login_required
@admin_required
def create_notification():
    """Create a notification for users."""
    from app.admin.forms import NotificationForm
    
    form = NotificationForm()
    
    if form.validate_on_submit():
        user_id = form.user.data if form.user.data != '0' else None
        title = form.title.data
        message = form.message.data
        
        if user_id:
            # Send to specific user
            user = User.query.get(user_id)
            if user:
                notification = Notification(
                    user_id=user.id,
                    title=title,
                    message=message
                )
                db.session.add(notification)
                flash(f'Notification sent to {user.username}.', 'success')
            else:
                flash('User not found.', 'danger')
        else:
            # Send to all users
            users = User.query.filter_by(is_active=True).all()
            for user in users:
                notification = Notification(
                    user_id=user.id,
                    title=title,
                    message=message
                )
                db.session.add(notification)
            flash(f'Notification sent to all users.', 'success')
        
        db.session.commit()
        logger.info(f"Admin {current_user.username} created notification: {title}")
        
        return redirect(url_for('admin.index'))
    
    # Get all users for select field
    users = User.query.filter_by(is_active=True).all()
    form.user.choices = [('0', 'All Users')] + [(str(user.id), user.username) for user in users]
    
    return render_template('admin/create_notification.html', 
                          title='Create Notification',
                          form=form,
                          app_name="NexusSync")