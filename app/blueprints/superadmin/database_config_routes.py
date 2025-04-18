# -------------------------------
# Imports
# -------------------------------
import json
import os
import shutil
import zipfile
from datetime import datetime
from io import BytesIO
from subprocess import CalledProcessError, check_output
from sqlalchemy.engine import url as sa_url
import subprocess
from flask import (
    Response,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from app.extensions import db
from .blueprint import superadmin_bp
from app.blueprints.superadmin.decorators import superadmin_required
from app.blueprints.superadmin.forms import CliForm, DatabaseConfigForm, QueryForm
from app.blueprints.superadmin.models.database_config import DatabaseConfig


# -------------------------------
# Utility Function: Backup Database for URI
# -------------------------------
def backup_for_uri(database_uri):
    """
    Given a database URI, returns the backup data and filename.
    Supports SQLite and PostgreSQL.
    """
    parsed = sa_url.make_url(database_uri)
    driver = parsed.get_driver_name()

    # Handle SQLite backups
    if driver in ("sqlite", "sqlite3", "pysqlite"):
        db_path = parsed.database
        if not os.path.exists(db_path):
            raise ValueError(f"SQLite file not found at {db_path}")
        with open(db_path, "rb") as f:
            data = f.read()
        return data, os.path.basename(db_path)

    # Handle PostgreSQL backups via pg_dump
    elif driver in ("postgresql", "postgresql+psycopg2"):
        cmd = ["pg_dump", "--format=custom", f"--dbname={database_uri}"]
        proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if proc.returncode != 0:
            raise ValueError(f"pg_dump failed: {proc.stderr.decode()}")
        return proc.stdout, f"{parsed.database}.dump"

    # Unsupported DB types
    else:
        raise ValueError(f"Unsupported database type: {driver}")


# -------------------------------
# Route: Database Tools Main Page
# -------------------------------
@superadmin_bp.route("/database-tools", methods=["GET", "POST"])
@superadmin_required
def database_tools():
    """
    Main page for database tools.
    - Allows running raw SQL queries.
    - Allows running CLI commands (limited).
    - Displays schema info.
    """
    active_tab = request.args.get("tab", "schema")
    query_form = QueryForm()
    cli_form = CliForm()
    query_result = None
    cli_output = None
    backup_message = None
    restore_message = None

    # Get schema metadata
    engine = db.get_engine(current_app)
    from sqlalchemy import inspect
    inspector = inspect(engine)
    schema_info = {
        table: [col["name"] for col in inspector.get_columns(table)]
        for table in inspector.get_table_names()
    }

    if request.method == "POST":
        if active_tab == "query" and query_form.validate_on_submit():
            sql_query = query_form.query.data
            try:
                with engine.connect() as conn:
                    result_proxy = conn.execute(text(sql_query))
                    query_result = {
                        "columns": result_proxy.keys(),
                        "rows": result_proxy.fetchall(),
                    }
            except SQLAlchemyError as e:
                flash(f"Error executing query: {str(e)}", "danger")
        elif active_tab == "cli" and cli_form.validate_on_submit():
            command = cli_form.command.data
            allowed = {
                "list_configs": "flask config list",
                "export_config": "flask config export",
                "test_db": "flask database-config/test-connection",
            }
            if command in allowed:
                try:
                    cli_output = check_output(allowed[command].split(), universal_newlines=True)
                except CalledProcessError as e:
                    cli_output = f"Error executing command: {str(e)}"
            else:
                cli_output = "Command not allowed."
    return render_template(
        "superadmin/database_tools.html",
        schema=schema_info,
        query_form=query_form,
        query_result=query_result,
        cli_form=cli_form,
        cli_output=cli_output,
        backup_message=backup_message,
        restore_message=restore_message,
        active_tab=active_tab,
    )


# -------------------------------
# Route: Database Configuration Settings
# -------------------------------
@superadmin_bp.route("/database-config", methods=["GET", "POST"], endpoint="database_config")
@superadmin_required
def database_config_view():
    """
    Manages connection info for a remote PostgreSQL database.
    Dynamically updates the bind URI if needed.
    """
    form = DatabaseConfigForm()
    if form.validate_on_submit():
        try:
            config = DatabaseConfig.query.first()
            if not config:
                config = DatabaseConfig(
                    db_host=form.db_host.data,
                    db_port=form.db_port.data,
                    db_name=form.db_name.data,
                    db_user=form.db_user.data,
                    db_password=form.db_password.data,
                    updated_by=current_user.id,
                )
                db.session.add(config)
            else:
                config.db_host = form.db_host.data
                config.db_port = form.db_port.data
                config.db_name = form.db_name.data
                config.db_user = form.db_user.data
                config.db_password = form.db_password.data
                config.updated_by = current_user.id

            db.session.commit()
            flash("Database configuration updated successfully.", "success")

            # Configure remote DB bind
            if form.db_host.data.lower() not in ["localhost", "127.0.0.1"]:
                remote_uri = (
                    f"postgresql://{form.db_user.data}:{form.db_password.data}@"
                    f"{form.db_host.data}:{form.db_port.data}/{form.db_name.data}"
                )
                current_app.config["SQLALCHEMY_BINDS"] = {"remote": remote_uri}
            else:
                current_app.config["SQLALCHEMY_BINDS"] = {}

            return redirect(url_for("superadmin.database_config"))
        except Exception as e:
            db.session.rollback()
            flash(f"Error updating database configuration: {str(e)}", "danger")

    elif request.method == "GET":
        config = DatabaseConfig.query.first()
        if config:
            form.db_host.data = config.db_host
            form.db_port.data = config.db_port
            form.db_name.data = config.db_name
            form.db_user.data = config.db_user
            form.db_password.data = config.db_password
        else:
            form.db_host.data = os.environ.get("PGHOST", "localhost")
            form.db_port.data = int(os.environ.get("PGPORT", "5432"))
            form.db_name.data = os.environ.get("PGDATABASE", "postgres")
            form.db_user.data = os.environ.get("PGUSER", "postgres")
            form.db_password.data = ""

    # Fake status values — to be enhanced
    db_status = {
        "status": "Connected",
        "db_type": current_app.config.get("SQLALCHEMY_DATABASE_URI", "Unknown"),
        "server_version": "Dynamic Server Version",
        "connection_pool": "Dynamic Pool Info",
        "ssl_encrypted": True,
    }
    config_env = {
        "FLASK_ENV": os.environ.get("FLASK_ENV", "[not set]"),
        "FLASK_APP": os.environ.get("FLASK_APP", "main.py"),
        "DATABASE_URL": os.environ.get("DATABASE_URL", "[hidden for security]"),
        "SESSION_SECRET": os.environ.get("SESSION_SECRET", "[hidden for security]"),
    }
    return render_template(
        "superadmin/database_config.html",
        form=form,
        db_status=db_status,
        config_env=config_env,
    )


# -------------------------------
# Route: Test DB Connection
# -------------------------------
@superadmin_bp.route("/database-config/test-connection")
@superadmin_required
def test_db_connection():
    """
    Tests internal and remote DB connections.
    Displays connection results using flash messages.
    """
    messages = []
    try:
        internal_engine = db.get_engine(app=current_app)
        with internal_engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        messages.append("Internal DB: Connected")
    except SQLAlchemyError as e:
        messages.append(f"Internal DB: Error - {str(e)}")

    binds = current_app.config.get("SQLALCHEMY_BINDS", {})
    if "remote" in binds:
        try:
            remote_engine = db.get_engine(app=current_app, bind="remote")
            with remote_engine.connect() as conn:
                conn.execute(text("SELECT 1"))
            messages.append("External DB: Connected")
        except SQLAlchemyError as e:
            messages.append(f"External DB: Error - {str(e)}")
    else:
        messages.append("External DB: Not Configured")

    flash(" | ".join(messages), "info")
    return redirect(url_for("superadmin.database_config"))


# -------------------------------
# Route: Execute Raw SQL Query
# -------------------------------
@superadmin_bp.route("/database-tools/run-sql-query", methods=["GET", "POST"])
@superadmin_required
def run_sql_query():
    """
    Allows superadmins to run arbitrary SQL queries through a form.
    Results are rendered below the form.
    """
    from app.blueprints.superadmin.forms import QueryForm  # local import

    form = QueryForm()
    query_result = None

    if form.validate_on_submit():
        sql_query = form.query.data
        try:
            engine = db.get_engine(current_app)
            with engine.connect() as conn:
                result_proxy = conn.execute(text(sql_query))
                query_result = {
                    "columns": result_proxy.keys(),
                    "rows": result_proxy.fetchall(),
                }
        except SQLAlchemyError as e:
            flash(f"Error executing query: {str(e)}", "danger")

    return render_template(
        "superadmin/run_sql_query.html",
        query_form=form,
        query_result=query_result,
    )


# -------------------------------
# Route: Backup Database
# -------------------------------
@superadmin_bp.route("/database-tools/backup-database", methods=["POST"])
@superadmin_required
def backup_database():
    """
    Creates ZIP archive containing backup(s) for internal and remote databases.
    Returns the archive as a downloadable file.
    """
    backup_files = {}
    errors = []

    # Backup default DB
    default_uri = current_app.config.get("SQLALCHEMY_DATABASE_URI")
    try:
        data, fname = backup_for_uri(default_uri)
        backup_files[fname] = data
    except Exception as e:
        errors.append(f"Default DB backup error: {str(e)}")

    # Backup all remote binds
    binds = current_app.config.get("SQLALCHEMY_BINDS", {})
    for key, uri in binds.items():
        try:
            data, fname = backup_for_uri(uri)
            backup_files[f"{key}_{fname}"] = data
        except Exception as e:
            errors.append(f"Backup error for bind '{key}': {str(e)}")

    # Handle backup errors
    if errors:
        flash(" | ".join(errors), "danger")
        return redirect(url_for("superadmin.database_tools", tab="backup"))

    # Prepare in-memory ZIP file
    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, "w", zipfile.ZIP_DEFLATED) as zf:
        for filename, content in backup_files.items():
            zf.writestr(filename, content)
    zip_buffer.seek(0)

    # Construct filename
    username = current_user.username if current_user.is_authenticated else "anonymous"
    timestamp = datetime.utcnow().strftime("%Y-%m-%d-%H-%M")
    zip_filename = f"DatabaseBackupBy{username}@{timestamp}.zip"

    # Serve ZIP file as HTTP response
    response = Response(zip_buffer.read(), mimetype="application/zip")
    response.headers["Content-Disposition"] = f'attachment; filename="{zip_filename}"'
    return response


# -------------------------------
# Route: Restore Database
# -------------------------------
@superadmin_bp.route("/database-tools/restore-database", methods=["GET", "POST"])
@superadmin_required
def restore_database():
    """
    Allows uploading a backup file and attempts to restore.
    Currently placeholder — actual restore logic is not yet implemented.
    """
    restore_message = None
    if request.method == "POST":
        if "backup_file" not in request.files:
            flash("No backup file provided.", "danger")
        else:
            file = request.files["backup_file"]
            if file.filename == "":
                flash("No selected file.", "danger")
            else:
                try:
                    backup_data = json.load(file)  # placeholder logic
                    restore_message = "Database restore functionality is not fully implemented."
                    flash(restore_message, "warning")
                except Exception as e:
                    flash(f"Error restoring database: {str(e)}", "danger")

    return render_template("superadmin/restore_database.html", restore_message=restore_message)


# -------------------------------
# Route: CLI Tools Run (POST)
# -------------------------------
@superadmin_bp.route("/database-tools/cli-tools-run", methods=["POST"])
@superadmin_required
def cli_tools_run():
    """
    Executes a safe, predefined CLI command (like `flask config list`) from the form.
    Displays the output using a flash message.
    """
    form = CliForm()
    cli_output = None

    if form.validate_on_submit():
        command = form.command.data
        allowed = {
            "list_configs": "flask config list",
            "export_config": "flask config export",
            "test_db": "flask database-config/test-connection",
        }
        if command in allowed:
            try:
                cli_output = check_output(allowed[command].split(), universal_newlines=True)
            except CalledProcessError as e:
                cli_output = f"Error executing command: {str(e)}"
        else:
            cli_output = "Command not allowed."

    flash(cli_output, "info")
    return redirect(url_for("superadmin.database_tools", tab="cli"))
