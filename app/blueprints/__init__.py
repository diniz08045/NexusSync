# Import individual blueprint instances
from .main import main_bp                       # Public/main site routes
from app.blueprints.superadmin.blueprint import superadmin_bp  # Superadmin-specific routes
from .filters import filters_bp                 # Custom filter routes (e.g. search, transforms)

def register_blueprints(app):
    """
    Register all application blueprints to the Flask app instance.

    This helps modularize route definitions and keeps the app structure clean.
    """

    # Register the main site/public routes
    app.register_blueprint(main_bp)

    # Register the superadmin panel routes
    app.register_blueprint(superadmin_bp)

    # Register any custom template filters or tools
    app.register_blueprint(filters_bp)
