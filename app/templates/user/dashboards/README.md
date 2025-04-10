# NexusSync Department-Specific Dashboards

This directory contains templates for department-specific dashboards that provide tailored experiences based on a user's department.

## Dashboard System Overview

The multi-dashboard routing system dynamically selects the appropriate dashboard template based on the user's department. This allows for presenting relevant information, metrics, and tools specific to each department's needs.

## Available Department Dashboards

The following department-specific dashboards are currently implemented:

- `default_dashboard.html` - Used when a user has no department or when a department-specific dashboard doesn't exist
- `it_dashboard.html` - Dashboard tailored for IT department staff
- `sales_dashboard.html` - Dashboard tailored for Sales department staff

## How to Add a New Department Dashboard

To create a new department-specific dashboard:

1. Create a new HTML template in this directory named `department_name_dashboard.html` (replacing department_name with the actual department slug)
2. Use the existing dashboards as a reference for structure and layout
3. Customize widgets, metrics, and department-specific tools as needed
4. The template will be automatically used for users with the matching department setting

## Dashboard Template Structure

Each dashboard template should:

1. Extend the `user_base.html` template: `{% extends 'user_base.html' %}`
2. Define content within the `{% block content %}` section
3. Include common elements like task metrics, notification counts, etc.
4. Add department-specific metrics, widgets, and tools

## Available Context Variables

The following variables are available in all dashboard templates:

- `current_user` - The current authenticated user object
- `unread_count` - Number of unread notifications
- `total_tasks` - Total tasks assigned to the user
- `completed_tasks` - Number of completed tasks
- `pending_tasks` - Number of pending tasks
- `completion_rate` - Percentage of completed tasks
- `created_tickets` - Number of tickets created by the user
- `assigned_tickets` - Number of tickets assigned to the user
- `open_assigned_tickets` - Number of open tickets assigned to the user
- `recent_tasks` - List of the user's most recent tasks
- `recent_tickets` - List of the user's most recent tickets
- `widgets` - Dictionary of enabled widgets for the department
- `department` - The user's department (as a string)

## Customizing Widget Availability

The `widgets` dictionary determines which widgets are displayed for each department. To modify widget availability:

1. Update the `get_department_widgets()` function in `app/utils/dashboard.py`
2. Add or modify department-specific widget configurations

## Best Practices

- Maintain a consistent layout and navigation structure across all dashboards
- Use the same base CSS with department-specific accents or branding
- Ensure all dashboards remain responsive and mobile-friendly
- Only display metrics and tools that are relevant to the specific department
- Keep the dashboard focused on daily tasks and common operations