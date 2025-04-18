import logging
from flask import Blueprint, render_template

# Initialize a logger for this module
logger = logging.getLogger(__name__)

# Define the main blueprint for public-facing routes
main_bp = Blueprint("main", __name__)


@main_bp.route("/")
def index():
    """
    Homepage view.

    This route renders the landing page for users who are not yet authenticated.
    Great for showcasing the product, branding, or basic navigation.
    """
    from datetime import datetime
    now = datetime.utcnow()
    return render_template(
        "main/index.html",
        title="Welcome",
        app_name="NexusSync",
        now=now
    )


@main_bp.route("/about")
def about():
    """
    About page view.

    Displays basic information about the project, company, or team.
    """
    return render_template("main/about.html", title="About", app_name="NexusSync")


@main_bp.route("/features")
def features():
    """
    Features page view.

    Lists what the platform offers—ideal for marketing or documentation.
    """
    return render_template("main/features.html", title="Features", app_name="NexusSync")


@main_bp.route("/contact")
def contact():
    """
    Contact page view.

    Provides users a way to reach out (email, phone, or form).
    """
    return render_template("main/contact.html", title="Contact", app_name="NexusSync")


@main_bp.route("/terms")
def terms():
    """
    Terms of Service page view.

    Legal stuff—what users agree to when using your app.
    """
    return render_template("main/terms.html", title="Terms of Service", app_name="NexusSync")


@main_bp.route("/privacy")
def privacy():
    """
    Privacy Policy page view.

    Outlines how user data is handled, stored, and protected.
    """
    return render_template("main/privacy.html", title="Privacy Policy", app_name="NexusSync")
