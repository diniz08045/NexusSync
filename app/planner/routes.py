import logging
from datetime import datetime, timedelta
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from app import db
from app.models.task import Task
from app.planner.forms import TaskForm

# Set up logger
logger = logging.getLogger(__name__)

# Create blueprint
planner_bp = Blueprint('planner', __name__, url_prefix='/planner')

@planner_bp.route('/')
@login_required
def index():
    """Planner dashboard with tasks, calendar, and productivity stats."""
    today = datetime.utcnow().date()
    
    # Get task counts for statistics
    total_tasks = Task.query.filter_by(user_id=current_user.id).count()
    completed_tasks = Task.query.filter_by(user_id=current_user.id, is_completed=True).count()
    pending_tasks = total_tasks - completed_tasks
    
    # Calculate completion rate
    completion_rate = (completed_tasks / total_tasks * 100) if total_tasks > 0 else 0
    
    # Tasks due today
    today_tasks = Task.query.filter_by(user_id=current_user.id).filter(
        Task.due_date >= today,
        Task.due_date < today + timedelta(days=1),
        Task.is_completed == False
    ).order_by(Task.priority.desc()).all()
    
    # Overdue tasks
    overdue_tasks = Task.query.filter_by(user_id=current_user.id).filter(
        Task.due_date < today,
        Task.is_completed == False
    ).order_by(Task.due_date.asc()).all()
    
    # Upcoming tasks
    upcoming_tasks = Task.query.filter_by(user_id=current_user.id).filter(
        Task.due_date >= today + timedelta(days=1),
        Task.is_completed == False
    ).order_by(Task.due_date.asc()).limit(5).all()
    
    # Recently completed tasks
    completed_tasks = Task.query.filter_by(user_id=current_user.id, is_completed=True).order_by(
        Task.completed_at.desc()
    ).limit(5).all()
    
    # Get all tasks for calendar view
    all_tasks = Task.query.filter_by(user_id=current_user.id).all()
    calendar_tasks = [
        {
            'id': task.id,
            'title': task.title,
            'start': task.due_date.isoformat() if task.due_date else None,
            'color': get_task_color(task),
            'url': url_for('planner.edit_task', task_id=task.id)
        }
        for task in all_tasks if task.due_date
    ]
    
    return render_template('planner/index.html', 
                           title='Planner', 
                           today_tasks=today_tasks,
                           overdue_tasks=overdue_tasks,
                           upcoming_tasks=upcoming_tasks,
                           completed_tasks=completed_tasks,
                           total_tasks=total_tasks,
                           completed_count=completed_tasks,
                           pending_tasks=pending_tasks,
                           completion_rate=completion_rate,
                           calendar_tasks=calendar_tasks,
                           app_name="NexusSync")

@planner_bp.route('/tasks')
@login_required
def tasks():
    """View all tasks."""
    # Get filter parameters
    filter_completed = request.args.get('completed', '')
    filter_category = request.args.get('category', '')
    filter_priority = request.args.get('priority', '')
    
    # Base query
    query = Task.query.filter_by(user_id=current_user.id)
    
    # Apply filters
    if filter_completed == 'yes':
        query = query.filter_by(is_completed=True)
    elif filter_completed == 'no':
        query = query.filter_by(is_completed=False)
    
    if filter_category:
        query = query.filter_by(category=filter_category)
    
    if filter_priority:
        query = query.filter_by(priority=filter_priority)
    
    # Get all categories for filter
    categories = db.session.query(Task.category).filter(
        Task.user_id == current_user.id,
        Task.category.isnot(None),
        Task.category != ''
    ).distinct().all()
    categories = [cat[0] for cat in categories]
    
    # Get all tasks with applied filters
    tasks = query.order_by(Task.is_completed, Task.due_date).all()
    
    return render_template('planner/tasks.html', 
                           title='My Tasks', 
                           tasks=tasks,
                           filter_completed=filter_completed,
                           filter_category=filter_category,
                           filter_priority=filter_priority,
                           categories=categories,
                           priorities=['low', 'medium', 'high', 'urgent'],
                           app_name="NexusSync")

@planner_bp.route('/tasks/create', methods=['GET', 'POST'])
@login_required
def create_task():
    """Create a new task."""
    form = TaskForm()
    
    if form.validate_on_submit():
        task = Task(
            user_id=current_user.id,
            title=form.title.data,
            description=form.description.data,
            due_date=form.due_date.data,
            priority=form.priority.data,
            category=form.category.data
        )
        db.session.add(task)
        db.session.commit()
        
        logger.info(f"User {current_user.username} created task {task.id}")
        flash('Task created successfully.', 'success')
        return redirect(url_for('planner.tasks'))
    
    return render_template('planner/edit_task.html', 
                           title='Create Task', 
                           form=form,
                           app_name="NexusSync")

@planner_bp.route('/tasks/<int:task_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_task(task_id):
    """Edit an existing task."""
    task = Task.query.filter_by(id=task_id, user_id=current_user.id).first_or_404()
    form = TaskForm()
    
    if form.validate_on_submit():
        task.title = form.title.data
        task.description = form.description.data
        task.due_date = form.due_date.data
        task.priority = form.priority.data
        task.category = form.category.data
        
        # If task is marked as completed and wasn't before
        if form.is_completed.data and not task.is_completed:
            task.mark_completed()
        # If task is marked as not completed but was before
        elif not form.is_completed.data and task.is_completed:
            task.is_completed = False
            task.completed_at = None
        
        db.session.commit()
        logger.info(f"User {current_user.username} updated task {task.id}")
        flash('Task updated successfully.', 'success')
        return redirect(url_for('planner.tasks'))
    
    elif request.method == 'GET':
        form.title.data = task.title
        form.description.data = task.description
        form.due_date.data = task.due_date
        form.priority.data = task.priority
        form.category.data = task.category
        form.is_completed.data = task.is_completed
    
    return render_template('planner/edit_task.html', 
                           title='Edit Task', 
                           form=form,
                           task=task,
                           app_name="NexusSync")

@planner_bp.route('/tasks/<int:task_id>/delete', methods=['POST'])
@login_required
def delete_task(task_id):
    """Delete a task."""
    task = Task.query.filter_by(id=task_id, user_id=current_user.id).first_or_404()
    
    db.session.delete(task)
    db.session.commit()
    
    logger.info(f"User {current_user.username} deleted task {task_id}")
    flash('Task deleted successfully.', 'success')
    return redirect(url_for('planner.tasks'))

@planner_bp.route('/tasks/<int:task_id>/toggle', methods=['POST'])
@login_required
def toggle_task_completion(task_id):
    """Toggle task completion status."""
    task = Task.query.filter_by(id=task_id, user_id=current_user.id).first_or_404()
    
    if task.is_completed:
        task.is_completed = False
        task.completed_at = None
        message = 'Task marked as incomplete.'
    else:
        task.mark_completed()
        message = 'Task marked as complete.'
    
    db.session.commit()
    logger.info(f"User {current_user.username} toggled completion for task {task_id}")
    
    # Return JSON if it's an AJAX request
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            'success': True,
            'is_completed': task.is_completed,
            'message': message,
            'task_id': task.id
        })
    
    flash(message, 'success')
    return redirect(url_for('planner.tasks'))

@planner_bp.route('/calendar')
@login_required
def calendar():
    """View calendar with tasks."""
    return render_template('planner/calendar.html', 
                           title='Calendar',
                           app_name="NexusSync")

@planner_bp.route('/api/calendar/events')
@login_required
def calendar_events():
    """API endpoint to get calendar events."""
    start_date = request.args.get('start', '')
    end_date = request.args.get('end', '')
    
    # Get all tasks for this user
    tasks = Task.query.filter_by(user_id=current_user.id).all()
    
    # Format tasks for FullCalendar
    events = [
        {
            'id': task.id,
            'title': task.title,
            'start': task.due_date.isoformat() if task.due_date else None,
            'color': get_task_color(task),
            'url': url_for('planner.edit_task', task_id=task.id)
        }
        for task in tasks if task.due_date
    ]
    
    return jsonify(events)

def get_task_color(task):
    """Get color for a task based on priority and completion status."""
    if task.is_completed:
        return '#28a745'  # Green
    
    if task.priority == 'urgent':
        return '#dc3545'  # Red
    elif task.priority == 'high':
        return '#fd7e14'  # Orange
    elif task.priority == 'medium':
        return '#ffc107'  # Yellow
    else:
        return '#17a2b8'  # Blue