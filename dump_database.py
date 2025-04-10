import os
import subprocess
import datetime

# Get database connection details from environment variables
db_url = os.environ.get('DATABASE_URL')
if not db_url:
    print("ERROR: DATABASE_URL environment variable not found.")
    exit(1)

# Parse the connection details
parts = db_url.replace('postgresql://', '').split('@')
user_pass = parts[0].split(':')
db_host_port = parts[1].split('/')

username = user_pass[0]
password = user_pass[1]

host_port = db_host_port[0].split(':')
host = host_port[0]
port = host_port[1] if len(host_port) > 1 else "5432"

db_name = db_host_port[1].split('?')[0]

# Create timestamp for the dump file
timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
dump_file = f"database_dump_{timestamp}.sql"

# Create pg_dump command
pg_dump_cmd = [
    "pg_dump",
    "-h", host,
    "-p", port,
    "-U", username,
    "-d", db_name,
    "-f", dump_file,
    "--no-owner",
    "--no-acl"
]

# Set PGPASSWORD environment variable
env = os.environ.copy()
env["PGPASSWORD"] = password

try:
    # Execute pg_dump
    print(f"Dumping database to {dump_file}...")
    subprocess.run(pg_dump_cmd, env=env, check=True)
    print(f"Database dump completed successfully. The file is: {dump_file}")
    print(f"You can download this file from the Replit Files panel.")
    
    # Print the file size
    file_size = os.path.getsize(dump_file)
    print(f"File size: {file_size / 1024:.2f} KB")
    
except subprocess.CalledProcessError as e:
    print(f"Failed to dump database: {e}")
except Exception as e:
    print(f"An error occurred: {e}")