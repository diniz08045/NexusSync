"""
Department-based dashboard routing utilities.
"""
from flask_login import current_user

def get_department_dashboard(department=None):
    """
    Get the appropriate dashboard template based on the user's department.
    
    Args:
        department: The department to get the dashboard for, defaults to current_user's department
        
    Returns:
        str: The template path for the department dashboard
    """
    if department is None and current_user.is_authenticated:
        department = current_user.department
    
    # Map departments to their dedicated dashboard templates
    department_dashboards = {
        'it': 'user/dashboards/it_dashboard.html',
        'marketing': 'user/dashboards/marketing_dashboard.html',
        'sales': 'user/dashboards/sales_dashboard.html',
        'hr': 'user/dashboards/hr_dashboard.html',
        'accounting': 'user/dashboards/accounting_dashboard.html',
        'support': 'user/dashboards/support_dashboard.html',
        'product': 'user/dashboards/product_dashboard.html',
        'legal': 'user/dashboards/legal_dashboard.html',
        'procurement': 'user/dashboards/procurement_dashboard.html',
        'logistics': 'user/dashboards/logistics_dashboard.html',
        'rnd': 'user/dashboards/rnd_dashboard.html',
        'training': 'user/dashboards/training_dashboard.html',
        'executive': 'user/dashboards/executive_dashboard.html',
        'communications': 'user/dashboards/communications_dashboard.html'
    }
    
    # If department exists and has a dedicated dashboard, return it
    if department and department in department_dashboards:
        return department_dashboards[department]
    
    # Otherwise, return the default dashboard
    return 'user/dashboards/default_dashboard.html'

def get_department_widgets(department=None):
    """
    Get the appropriate dashboard widgets based on the user's department.
    
    Args:
        department: The department to get widgets for, defaults to current_user's department
        
    Returns:
        dict: A dictionary of widgets and their configurations
    """
    if department is None and current_user.is_authenticated:
        department = current_user.department
    
    # Default widgets that appear on all dashboards
    default_widgets = {
        'notifications': True,
        'tasks': True,
        'recent_activity': True,
        'calendar': True
    }
    
    # Department-specific widgets
    department_widgets = {
        'it': {
            'tickets': True,
            'system_status': True,
            'network_monitor': True,
            'service_requests': True
        },
        'marketing': {
            'campaigns': True,
            'social_media': True,
            'content_calendar': True,
            'analytics': True
        },
        'sales': {
            'deals': True,
            'prospects': True,
            'quotas': True,
            'performance': True
        },
        'hr': {
            'employees': True,
            'onboarding': True,
            'leave_requests': True,
            'performance_reviews': True
        },
        'accounting': {
            'invoices': True,
            'expenses': True,
            'budgets': True,
            'financial_reports': True
        },
        'support': {
            'tickets': True,
            'knowledge_base': True,
            'customer_satisfaction': True,
            'escalations': True
        },
        'product': {
            'roadmap': True,
            'sprints': True,
            'bugs': True,
            'feature_requests': True
        },
        'legal': {
            'contracts': True,
            'compliance': True,
            'cases': True,
            'regulatory_updates': True
        },
        'procurement': {
            'purchase_orders': True,
            'vendors': True,
            'inventory': True,
            'rfps': True
        },
        'logistics': {
            'shipments': True,
            'inventory': True,
            'warehouses': True,
            'delivery_status': True
        },
        'rnd': {
            'projects': True,
            'experiments': True,
            'patents': True,
            'publications': True
        },
        'training': {
            'courses': True,
            'enrollments': True,
            'feedback': True,
            'certifications': True
        },
        'executive': {
            'kpis': True,
            'reports': True,
            'strategic_initiatives': True,
            'board_meetings': True
        },
        'communications': {
            'press_releases': True,
            'media_coverage': True,
            'internal_comms': True,
            'events': True
        }
    }
    
    # Combine default widgets with department-specific widgets
    widgets = default_widgets.copy()
    if department and department in department_widgets:
        widgets.update(department_widgets[department])
    
    return widgets