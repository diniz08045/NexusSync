from datetime import datetime
from flask import Blueprint

# Create a reusable blueprint for custom Jinja filters
filters_bp = Blueprint('filters', __name__)

@filters_bp.app_template_filter('timeago')
def timeago_filter(date):
    """
    Jinja2 filter to display human-readable 'time ago' strings.
    Turns a datetime into phrases like:
      - 'Just now'
      - '5 minutes ago'
      - '2 days ago'
      - '1 month ago'

    Args:
        date (datetime): The datetime to compare against now.

    Returns:
        str: A relative time string.
    """
    if not date:
        return ''

    now = datetime.utcnow()
    diff = now - date
    seconds = diff.total_seconds()

    # Seconds
    if seconds < 60:
        return 'Just now'

    # Minutes
    minutes = int(seconds / 60)
    if minutes == 1:
        return '1 minute ago'
    if minutes < 60:
        return f'{minutes} minutes ago'

    # Hours
    hours = int(minutes / 60)
    if hours == 1:
        return '1 hour ago'
    if hours < 24:
        return f'{hours} hours ago'

    # Days
    days = int(hours / 24)
    if days == 1:
        return 'Yesterday'
    if days < 7:
        return f'{days} days ago'

    # Weeks
    weeks = int(days / 7)
    if weeks == 1:
        return '1 week ago'
    if weeks < 4:
        return f'{weeks} weeks ago'

    # Months (rough estimate)
    months = int(days / 30)
    if months == 1:
        return '1 month ago'
    if months < 12:
        return f'{months} months ago'

    # Years
    years = int(days / 365)
    if years == 1:
        return '1 year ago'
    return f'{years} years ago'
