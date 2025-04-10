import logging
from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from app import db
from app.models.client import Client
from app.clients.forms import ClientForm
from app.utils.decorators import admin_required

# Set up logger
logger = logging.getLogger(__name__)

# Create blueprint
clients_bp = Blueprint('clients', __name__, url_prefix='/clients')

@clients_bp.route('/')
@login_required
def index():
    """Client dashboard showing all clients."""
    # Get filter parameters
    filter_active = request.args.get('active', '')
    search_query = request.args.get('q', '')
    
    # Build query
    query = Client.query
    
    # Apply filters
    if filter_active == 'yes':
        query = query.filter_by(is_active=True)
    elif filter_active == 'no':
        query = query.filter_by(is_active=False)
    
    # Apply search
    if search_query:
        query = query.filter(
            (Client.name.ilike(f'%{search_query}%')) |
            (Client.email.ilike(f'%{search_query}%')) |
            (Client.company.ilike(f'%{search_query}%'))
        )
    
    # Get clients with applied filters
    clients = query.order_by(Client.name).all()
    
    return render_template('clients/index.html', 
                           title='Clients',
                           clients=clients,
                           filter_active=filter_active,
                           search_query=search_query,
                           app_name="NexusSync")

@clients_bp.route('/create', methods=['GET', 'POST'])
@login_required
def create_client():
    """Create a new client."""
    form = ClientForm()
    
    if form.validate_on_submit():
        client = Client(
            name=form.name.data,
            email=form.email.data,
            phone=form.phone.data,
            company=form.company.data,
            address=form.address.data,
            city=form.city.data,
            state=form.state.data,
            zip_code=form.zip_code.data,
            country=form.country.data,
            is_active=True,
            notes=form.notes.data
        )
        db.session.add(client)
        db.session.commit()
        
        logger.info(f"User {current_user.username} created client {client.id}")
        flash('Client created successfully.', 'success')
        return redirect(url_for('clients.view_client', client_id=client.id))
    
    return render_template('clients/edit_client.html', 
                           title='Create Client',
                           form=form,
                           app_name="NexusSync")

@clients_bp.route('/<int:client_id>')
@login_required
def view_client(client_id):
    """View a client and its details."""
    client = Client.query.get_or_404(client_id)
    
    return render_template('clients/view_client.html',
                           title=client.name,
                           client=client,
                           app_name="NexusSync")

@clients_bp.route('/<int:client_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_client(client_id):
    """Edit an existing client."""
    client = Client.query.get_or_404(client_id)
    form = ClientForm()
    
    if form.validate_on_submit():
        client.name = form.name.data
        client.email = form.email.data
        client.phone = form.phone.data
        client.company = form.company.data
        client.address = form.address.data
        client.city = form.city.data
        client.state = form.state.data
        client.zip_code = form.zip_code.data
        client.country = form.country.data
        client.is_active = form.is_active.data
        client.notes = form.notes.data
        
        db.session.commit()
        logger.info(f"User {current_user.username} updated client {client.id}")
        flash('Client updated successfully.', 'success')
        return redirect(url_for('clients.view_client', client_id=client.id))
    
    elif request.method == 'GET':
        form.name.data = client.name
        form.email.data = client.email
        form.phone.data = client.phone
        form.company.data = client.company
        form.address.data = client.address
        form.city.data = client.city
        form.state.data = client.state
        form.zip_code.data = client.zip_code
        form.country.data = client.country
        form.is_active.data = client.is_active
        form.notes.data = client.notes
    
    return render_template('clients/edit_client.html',
                           title=f'Edit {client.name}',
                           form=form,
                           client=client,
                           app_name="NexusSync")

@clients_bp.route('/<int:client_id>/delete', methods=['POST'])
@login_required
@admin_required
def delete_client(client_id):
    """Delete a client (admin only)."""
    client = Client.query.get_or_404(client_id)
    
    name = client.name
    db.session.delete(client)
    db.session.commit()
    
    logger.info(f"Admin {current_user.username} deleted client {name}")
    flash(f'Client {name} has been deleted.', 'success')
    return redirect(url_for('clients.index'))

@clients_bp.route('/<int:client_id>/toggle_status', methods=['POST'])
@login_required
def toggle_client_status(client_id):
    """Toggle client active status."""
    client = Client.query.get_or_404(client_id)
    
    client.is_active = not client.is_active
    db.session.commit()
    
    status = 'activated' if client.is_active else 'deactivated'
    logger.info(f"User {current_user.username} {status} client {client.id}")
    flash(f'Client {client.name} has been {status}.', 'success')
    
    # Return JSON if it's an AJAX request
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return jsonify({
            'success': True,
            'is_active': client.is_active,
            'client_id': client.id,
            'message': f'Client {client.name} has been {status}.'
        })
    
    return redirect(url_for('clients.view_client', client_id=client.id))