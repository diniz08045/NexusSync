from app.extensions import db

# ========================================
# Association Table: user_roles
# ========================================
# This table establishes a many-to-many relationship between users and roles.
# Each row links one user to one role using foreign keys.
# The combination of (user_id, role_id) is unique and acts as a composite primary key.

user_roles = db.Table(
    "user_roles",
    db.Column("user_id", db.Integer, db.ForeignKey("user.id"), primary_key=True),  # References a user
    db.Column("role_id", db.Integer, db.ForeignKey("role.id"), primary_key=True),  # References a role
)
