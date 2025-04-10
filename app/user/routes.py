import logging
from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from app import db
from app.models.user import User
from app.models.notification import Notification
from app.user.forms import EditProfileForm, ChangePasswordForm
from app.utils.decorators import check_confirmed_email

# Set up logger
logger = logging.getLogger(__name__)

# Create blueprint
user_bp = Blueprint('user', __name__, url_prefix='/user')

@user_bp.before_request
def before_request():
    """Run before each request in user blueprint."""
    if current_user.is_authenticated:
        current_user.last_activity = datetime.utcnow()
        db.session.commit()

@user_bp.route('/')
@user_bp.route('/index')
@login_required
def index():
    """User dashboard homepage."""
    # Fetch unread notifications count
    unread_count = current_user.unread_notifications_count()
    
    # Get stats for dashboard widgets
    from app.models.task import Task
    from app.models.ticket import Ticket
    from app.utils.dashboard import get_department_dashboard, get_department_widgets
    
    # Tasks stats
    total_tasks = Task.query.filter_by(user_id=current_user.id).count()
    completed_tasks = Task.query.filter_by(user_id=current_user.id, is_completed=True).count()
    pending_tasks = total_tasks - completed_tasks
    completion_rate = (completed_tasks / total_tasks * 100) if total_tasks > 0 else 0
    
    # Tickets stats
    created_tickets = Ticket.query.filter_by(creator_id=current_user.id).count()
    assigned_tickets = Ticket.query.filter_by(assignee_id=current_user.id).count()
    open_assigned_tickets = Ticket.query.filter_by(
        assignee_id=current_user.id, 
        status='open'
    ).count()
    
    # Recent activities
    recent_tasks = Task.query.filter_by(user_id=current_user.id).order_by(
        Task.updated_at.desc()
    ).limit(5).all()
    
    recent_tickets = Ticket.query.filter(
        (Ticket.creator_id == current_user.id) | 
        (Ticket.assignee_id == current_user.id)
    ).order_by(Ticket.updated_at.desc()).limit(5).all()
    
    # Get department-specific dashboard template
    dashboard_template = get_department_dashboard()
    
    # Get department-specific widgets
    widgets = get_department_widgets()
    
    # Get department name for display purposes
    department_display = current_user.department.replace('_', ' ').title() if current_user.department else 'Default'
    
    return render_template(dashboard_template, 
                          title=f'{department_display} Dashboard',
                          unread_count=unread_count,
                          total_tasks=total_tasks,
                          completed_tasks=completed_tasks,
                          pending_tasks=pending_tasks,
                          completion_rate=completion_rate,
                          created_tickets=created_tickets,
                          assigned_tickets=assigned_tickets,
                          open_assigned_tickets=open_assigned_tickets,
                          recent_tasks=recent_tasks,
                          recent_tickets=recent_tickets,
                          widgets=widgets,
                          department=current_user.department,
                          app_name="NexusSync")

@user_bp.route('/profile')
@login_required
def profile():
    """User profile page."""
    return render_template('user/profile.html', 
                          title='My Profile',
                          user=current_user,
                          app_name="NexusSync")

@user_bp.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    """Edit user profile page."""
    form = EditProfileForm(current_user.username, current_user.email)
    
    if form.validate_on_submit():
        current_user.username = form.username.data
        current_user.email = form.email.data
        current_user.first_name = form.first_name.data
        current_user.last_name = form.last_name.data
        current_user.department = form.department.data
        
        db.session.commit()
        
        logger.info(f"User {current_user.username} updated their profile")
        flash('Your profile has been updated.', 'success')
        return redirect(url_for('user.profile'))
    
    elif request.method == 'GET':
        form.username.data = current_user.username
        form.email.data = current_user.email
        form.first_name.data = current_user.first_name
        form.last_name.data = current_user.last_name
        form.department.data = current_user.department
    
    return render_template('user/edit_profile.html', 
                          title='Edit Profile',
                          form=form,
                          app_name="NexusSync")

@user_bp.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """Change user password page."""
    form = ChangePasswordForm()
    
    if form.validate_on_submit():
        if not current_user.check_password(form.current_password.data):
            flash('Current password is incorrect.', 'danger')
            return redirect(url_for('user.change_password'))
        
        current_user.set_password(form.new_password.data)
        db.session.commit()
        
        logger.info(f"User {current_user.username} changed their password")
        flash('Your password has been changed.', 'success')
        return redirect(url_for('user.profile'))
    
    return render_template('user/change_password.html', 
                          title='Change Password',
                          form=form,
                          app_name="NexusSync")

@user_bp.route('/notifications')
@login_required
def notifications():
    """User notifications page."""
    page = request.args.get('page', 1, type=int)
    per_page = 20
    
    notifications = Notification.query.filter_by(
        user_id=current_user.id
    ).order_by(
        Notification.is_read,
        Notification.created_at.desc()
    ).paginate(page=page, per_page=per_page, error_out=False)
    
    # Mark all notifications as read
    unread = Notification.query.filter_by(
        user_id=current_user.id,
        is_read=False
    ).all()
    
    for notification in unread:
        notification.is_read = True
    
    db.session.commit()
    
    return render_template('user/notifications.html', 
                          title='My Notifications',
                          notifications=notifications,
                          app_name="NexusSync")

@user_bp.route('/notifications/<int:notification_id>/dismiss', methods=['POST'])
@login_required
def dismiss_notification(notification_id):
    """Dismiss a notification."""
    notification = Notification.query.filter_by(
        id=notification_id,
        user_id=current_user.id
    ).first_or_404()
    
    notification.is_dismissed = True
    db.session.commit()
    
    # Return JSON if it's an AJAX request
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            'success': True,
            'message': 'Notification dismissed.'
        })
    
    flash('Notification dismissed.', 'success')
    return redirect(url_for('user.notifications'))

@user_bp.route('/notifications/dismiss-all', methods=['POST'])
@login_required
def dismiss_all_notifications():
    """Dismiss all notifications for the current user."""
    notifications = Notification.query.filter_by(
        user_id=current_user.id,
        is_dismissed=False
    ).all()
    
    for notification in notifications:
        notification.is_dismissed = True
    
    db.session.commit()
    
    # Return JSON if it's an AJAX request
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            'success': True,
            'message': 'All notifications dismissed.'
        })
    
    flash('All notifications have been dismissed.', 'success')
    return redirect(url_for('user.notifications'))

@user_bp.route('/search')
@login_required
def search():
    """Global search across the application."""
    query = request.args.get('q', '')
    
    if not query:
        return redirect(url_for('user.index'))
    
    # Get results from different models
    from app.models.task import Task
    from app.models.ticket import Ticket
    from app.models.client import Client
    
    # Get tasks
    tasks = Task.query.filter(
        Task.user_id == current_user.id,
        (Task.title.ilike(f'%{query}%') | Task.description.ilike(f'%{query}%'))
    ).limit(5).all()
    
    # Get tickets
    tickets = Ticket.query.filter(
        ((Ticket.creator_id == current_user.id) | (Ticket.assignee_id == current_user.id)),
        (Ticket.title.ilike(f'%{query}%') | Ticket.description.ilike(f'%{query}%'))
    ).limit(5).all()
    
    # Get clients (if admin or has access)
    clients = Client.query.filter(
        (Client.name.ilike(f'%{query}%') | 
         Client.email.ilike(f'%{query}%') | 
         Client.company.ilike(f'%{query}%'))
    ).limit(5).all()
    
    # Return JSON if it's an AJAX request
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        results = {
            'tasks': [{'id': t.id, 'title': t.title, 'url': url_for('planner.edit_task', task_id=t.id)} for t in tasks],
            'tickets': [{'id': t.id, 'title': t.title, 'url': url_for('tickets.view_ticket', ticket_id=t.id)} for t in tickets],
            'clients': [{'id': c.id, 'name': c.name, 'url': url_for('clients.view_client', client_id=c.id)} for c in clients],
        }
        return jsonify(results)
    
    return render_template('user/search_results.html', 
                          title=f'Search Results for "{query}"',
                          query=query,
                          tasks=tasks,
                          tickets=tickets,
                          clients=clients,
                          app_name="NexusSync")

@user_bp.route('/settings')
@login_required
def settings():
    """User settings page."""
    return render_template('user/settings.html', 
                          title='Settings',
                          user=current_user,
                          app_name="NexusSync")

@user_bp.route('/settings/security')
@login_required
def security_settings():
    """User security settings page."""
    # Recent sessions
    from app.models.session import SessionActivity
    
    recent_sessions = SessionActivity.query.filter_by(
        user_id=current_user.id
    ).order_by(
        SessionActivity.last_activity.desc()
    ).limit(5).all()
    
    return render_template('user/security_settings.html', 
                          title='Security Settings',
                          user=current_user,
                          recent_sessions=recent_sessions,
                          app_name="NexusSync")

@user_bp.route('/settings/notifications')
@login_required
def notification_settings():
    """User notification settings page."""
    return render_template('user/notification_settings.html', 
                          title='Notification Settings',
                          user=current_user,
                          app_name="NexusSync")

@user_bp.route('/settings/two-factor', methods=['GET', 'POST'])
@login_required
@check_confirmed_email
def two_factor_settings():
    """Two-factor authentication settings page."""
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'enable':
            # Enable two-factor authentication
            current_user.two_factor_enabled = True
            db.session.commit()
            
            logger.info(f"User {current_user.username} enabled 2FA")
            flash('Two-factor authentication has been enabled.', 'success')
        
        elif action == 'disable':
            # Disable two-factor authentication
            current_user.two_factor_enabled = False
            db.session.commit()
            
            logger.info(f"User {current_user.username} disabled 2FA")
            flash('Two-factor authentication has been disabled.', 'success')
    
    return render_template('user/two_factor_settings.html', 
                          title='Two-Factor Authentication',
                          user=current_user,
                          app_name="NexusSync")