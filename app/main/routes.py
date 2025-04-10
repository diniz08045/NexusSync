import logging
from flask import Blueprint, render_template, redirect, url_for

# Set up logger
logger = logging.getLogger(__name__)

# Create blueprint
main_bp = Blueprint('main', __name__)

@main_bp.route('/')
def index():
    """Landing page for non-authenticated users."""
    return render_template('main/index.html', title='Welcome', app_name="NexusSync")

@main_bp.route('/about')
def about():
    """About page."""
    return render_template('main/about.html', title='About', app_name="NexusSync")

@main_bp.route('/features')
def features():
    """Features page."""
    return render_template('main/features.html', title='Features', app_name="NexusSync")

@main_bp.route('/contact')
def contact():
    """Contact page."""
    return render_template('main/contact.html', title='Contact Us', app_name="NexusSync")

@main_bp.route('/terms')
def terms():
    """Terms of service page."""
    return render_template('main/terms.html', title='Terms of Service', app_name="NexusSync")

@main_bp.route('/privacy')
def privacy():
    """Privacy policy page."""
    return render_template('main/privacy.html', title='Privacy Policy', app_name="NexusSync")