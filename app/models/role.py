from app.extensions import db

# ========================================
# Association Table: user_roles
# ========================================
# Defines a many-to-many relationship between Users and Roles.
# Each record connects one user to one role.
user_roles = db.Table(
    "user_roles",
    db.Column("user_id", db.Integer, db.ForeignKey("user.id"), primary_key=True),  # User reference
    db.Column("role_id", db.Integer, db.ForeignKey("role.id"), primary_key=True),  # Role reference
)


# ========================================
# Model: Role
# ========================================
class Role(db.Model):
    """
    Represents a role that can be assigned to users.
    Examples include 'user', 'admin', 'superadmin', etc.
    """

    id = db.Column(db.Integer, primary_key=True)

    # Unique name for the role (e.g., "admin")
    name = db.Column(db.String(64), unique=True, nullable=False)

    # Optional description of what the role entails
    description = db.Column(db.String(256))

    def __repr__(self):
        """Return a readable string representation of the Role."""
        return f"<Role {self.name}>"
