from datetime import datetime
from flask import Blueprint

# Create a blueprint for the filters
filters_bp = Blueprint('filters', __name__)

@filters_bp.app_template_filter('timeago')
def timeago_filter(date):
    """
    Convert a datetime object to a relative time string like "5 minutes ago" or "2 days ago".
    
    Args:
        date: A datetime object to convert
        
    Returns:
        str: A human-readable relative time string
    """
    if not date:
        return ''
    
    now = datetime.utcnow()
    diff = now - date
    
    seconds = diff.total_seconds()
    
    if seconds < 60:
        return 'Just now'
    
    minutes = int(seconds / 60)
    if minutes == 1:
        return '1 minute ago'
    if minutes < 60:
        return f'{minutes} minutes ago'
    
    hours = int(minutes / 60)
    if hours == 1:
        return '1 hour ago'
    if hours < 24:
        return f'{hours} hours ago'
    
    days = int(hours / 24)
    if days == 1:
        return 'Yesterday'
    if days < 7:
        return f'{days} days ago'
    
    weeks = int(days / 7)
    if weeks == 1:
        return '1 week ago'
    if weeks < 4:
        return f'{weeks} weeks ago'
    
    months = int(days / 30)
    if months == 1:
        return '1 month ago'
    if months < 12:
        return f'{months} months ago'
    
    years = int(days / 365)
    if years == 1:
        return '1 year ago'
    
    return f'{years} years ago'