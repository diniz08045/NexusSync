from werkzeug.security import generate_password_hash

# Generate a proper password hash for a simple password
password = "123456"
password_hash = generate_password_hash(password)
print(f"Password hash for '{password}': {password_hash}")