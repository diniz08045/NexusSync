import logging
from datetime import datetime
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from app import db
from app.models.ticket import Ticket
from app.models.user import User
from app.tickets.forms import TicketForm, CommentForm

# Set up logger
logger = logging.getLogger(__name__)

# Create blueprint
tickets_bp = Blueprint('tickets', __name__, url_prefix='/tickets')

@tickets_bp.route('/')
@login_required
def index():
    """Ticket dashboard showing tickets created by or assigned to the user."""
    # Get filter parameters
    filter_status = request.args.get('status', '')
    filter_priority = request.args.get('priority', '')
    assigned_only = request.args.get('assigned', '') == 'yes'
    created_only = request.args.get('created', '') == 'yes'
    
    # Build query
    if assigned_only and not created_only:
        # Only assigned tickets
        query = Ticket.query.filter_by(assignee_id=current_user.id)
    elif created_only and not assigned_only:
        # Only created tickets
        query = Ticket.query.filter_by(creator_id=current_user.id)
    else:
        # Both created and assigned tickets
        query = Ticket.query.filter(
            (Ticket.creator_id == current_user.id) | 
            (Ticket.assignee_id == current_user.id)
        )
    
    # Apply filters
    if filter_status:
        query = query.filter_by(status=filter_status)
    
    if filter_priority:
        query = query.filter_by(priority=filter_priority)
    
    # Get tickets with applied filters
    tickets = query.order_by(Ticket.created_at.desc()).all()
    
    # Get all ticket statuses and priorities for filters
    statuses = ['open', 'in_progress', 'resolved', 'closed']
    priorities = ['low', 'medium', 'high', 'critical']
    
    return render_template('tickets/index.html', 
                           title='Tickets',
                           tickets=tickets,
                           filter_status=filter_status,
                           filter_priority=filter_priority,
                           assigned_only=assigned_only,
                           created_only=created_only,
                           statuses=statuses,
                           priorities=priorities,
                           app_name="NexusSync")

@tickets_bp.route('/create', methods=['GET', 'POST'])
@login_required
def create_ticket():
    """Create a new ticket."""
    form = TicketForm()
    
    # Populate assignee choices
    form.assignee_id.choices = [(0, 'Unassigned')] + [
        (user.id, f"{user.first_name} {user.last_name} ({user.username})")
        for user in User.query.filter_by(is_active=True).order_by(User.username).all()
    ]
    
    if form.validate_on_submit():
        ticket = Ticket(
            title=form.title.data,
            description=form.description.data,
            status='open',
            priority=form.priority.data,
            creator_id=current_user.id,
            assignee_id=form.assignee_id.data if form.assignee_id.data != 0 else None,
            due_date=form.due_date.data,
            category=form.category.data
        )
        db.session.add(ticket)
        db.session.commit()
        
        logger.info(f"User {current_user.username} created ticket {ticket.id}")
        flash('Ticket created successfully.', 'success')
        return redirect(url_for('tickets.view_ticket', ticket_id=ticket.id))
    
    return render_template('tickets/edit_ticket.html', 
                           title='Create Ticket',
                           form=form,
                           app_name="NexusSync")

@tickets_bp.route('/<int:ticket_id>')
@login_required
def view_ticket(ticket_id):
    """View a ticket and its details."""
    ticket = Ticket.query.get_or_404(ticket_id)
    
    # Check if user has access to this ticket
    if not (ticket.creator_id == current_user.id or 
            ticket.assignee_id == current_user.id or 
            current_user.is_admin()):
        flash('You do not have permission to view this ticket.', 'danger')
        return redirect(url_for('tickets.index'))
    
    # Comment form for adding comments
    comment_form = CommentForm()
    
    return render_template('tickets/view_ticket.html',
                           title=f'Ticket #{ticket.id}',
                           ticket=ticket,
                           comment_form=comment_form,
                           app_name="NexusSync")

@tickets_bp.route('/<int:ticket_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_ticket(ticket_id):
    """Edit an existing ticket."""
    ticket = Ticket.query.get_or_404(ticket_id)
    
    # Check if user has permission to edit
    if not (ticket.creator_id == current_user.id or 
            ticket.assignee_id == current_user.id or 
            current_user.is_admin()):
        flash('You do not have permission to edit this ticket.', 'danger')
        return redirect(url_for('tickets.index'))
    
    form = TicketForm()
    
    # Populate assignee choices
    form.assignee_id.choices = [(0, 'Unassigned')] + [
        (user.id, f"{user.first_name} {user.last_name} ({user.username})")
        for user in User.query.filter_by(is_active=True).order_by(User.username).all()
    ]
    
    # Add status field for editing
    form.status = SelectField('Status', choices=[
        ('open', 'Open'),
        ('in_progress', 'In Progress'),
        ('resolved', 'Resolved'),
        ('closed', 'Closed')
    ])
    
    if form.validate_on_submit():
        ticket.title = form.title.data
        ticket.description = form.description.data
        ticket.status = form.status.data
        ticket.priority = form.priority.data
        ticket.assignee_id = form.assignee_id.data if form.assignee_id.data != 0 else None
        ticket.due_date = form.due_date.data
        ticket.category = form.category.data
        ticket.updated_at = datetime.utcnow()
        
        # If status changed to resolved and wasn't before
        if form.status.data == 'resolved' and ticket.status != 'resolved':
            ticket.resolved_at = datetime.utcnow()
        
        db.session.commit()
        logger.info(f"User {current_user.username} updated ticket {ticket.id}")
        flash('Ticket updated successfully.', 'success')
        return redirect(url_for('tickets.view_ticket', ticket_id=ticket.id))
    
    elif request.method == 'GET':
        form.title.data = ticket.title
        form.description.data = ticket.description
        form.status.data = ticket.status
        form.priority.data = ticket.priority
        form.assignee_id.data = ticket.assignee_id if ticket.assignee_id else 0
        form.due_date.data = ticket.due_date
        form.category.data = ticket.category
    
    return render_template('tickets/edit_ticket.html',
                           title=f'Edit Ticket #{ticket.id}',
                           form=form,
                           ticket=ticket,
                           app_name="NexusSync")

@tickets_bp.route('/<int:ticket_id>/assign', methods=['POST'])
@login_required
def assign_ticket(ticket_id):
    """Assign a ticket to a user."""
    ticket = Ticket.query.get_or_404(ticket_id)
    
    # Check permission
    if not (ticket.creator_id == current_user.id or current_user.is_admin()):
        flash('You do not have permission to assign this ticket.', 'danger')
        return redirect(url_for('tickets.view_ticket', ticket_id=ticket.id))
    
    assignee_id = request.form.get('assignee_id', type=int)
    if assignee_id:
        user = User.query.get_or_404(assignee_id)
        ticket.assignee_id = user.id
        ticket.updated_at = datetime.utcnow()
        db.session.commit()
        
        logger.info(f"User {current_user.username} assigned ticket {ticket.id} to {user.username}")
        flash(f'Ticket assigned to {user.username}.', 'success')
    else:
        ticket.assignee_id = None
        ticket.updated_at = datetime.utcnow()
        db.session.commit()
        
        logger.info(f"User {current_user.username} unassigned ticket {ticket.id}")
        flash('Ticket unassigned.', 'success')
    
    return redirect(url_for('tickets.view_ticket', ticket_id=ticket.id))

@tickets_bp.route('/<int:ticket_id>/status', methods=['POST'])
@login_required
def change_status(ticket_id):
    """Change the status of a ticket."""
    ticket = Ticket.query.get_or_404(ticket_id)
    
    # Check permission
    if not (ticket.creator_id == current_user.id or 
            ticket.assignee_id == current_user.id or 
            current_user.is_admin()):
        flash('You do not have permission to change this ticket status.', 'danger')
        return redirect(url_for('tickets.view_ticket', ticket_id=ticket.id))
    
    status = request.form.get('status')
    if status in ['open', 'in_progress', 'resolved', 'closed']:
        old_status = ticket.status
        ticket.status = status
        ticket.updated_at = datetime.utcnow()
        
        # If status changed to resolved and wasn't before
        if status == 'resolved' and old_status != 'resolved':
            ticket.resolved_at = datetime.utcnow()
        
        db.session.commit()
        
        logger.info(f"User {current_user.username} changed ticket {ticket.id} status from {old_status} to {status}")
        flash(f'Ticket status changed to {status}.', 'success')
    else:
        flash('Invalid status.', 'danger')
    
    return redirect(url_for('tickets.view_ticket', ticket_id=ticket.id))