import click
from flask import current_app

from app.extensions import db
from app.blueprints.superadmin.config_keys import CONFIG_CASTS, to_str
from app.blueprints.superadmin.models.system_config import SystemConfig


def register_config_cli(app):
    # Register a top-level CLI group called "config"
    @app.cli.group("config")
    def config_cli():
        """System configuration commands."""
        # You can run `flask config list`, `flask config set`, etc.

    @config_cli.command("list")
    def list_configs():
        """List all system configuration settings."""
        with app.app_context():
            configs = SystemConfig.query.all()
            if not configs:
                click.echo("No system configuration entries found.")
                return

            click.echo("System Configuration:\n")
            for conf in configs:
                # Print each key with the current value from app.config
                val = current_app.config.get(conf.key, "[not loaded]")
                click.echo(f"{conf.key} = {val}")

    @config_cli.command("get")
    @click.argument("key")
    def get_config(key):
        """Get the value of a specific configuration key."""
        with app.app_context():
            key = key.upper()
            value = current_app.config.get(key)
            if value is not None:
                click.echo(f"{key} = {value}")
            else:
                click.echo(f"Key '{key}' not found in app.config")

    @config_cli.command("set")
    @click.argument("key")
    @click.argument("value")
    def set_config(key, value):
        """Set or update a system configuration key."""
        with app.app_context():
            key = key.upper()

            # Look for the existing config entry in the DB
            config = SystemConfig.query.filter_by(key=key).first()

            # Use type-safe casting if available, fallback to string
            cast_func = CONFIG_CASTS.get(key, to_str)

            try:
                # Validate that the value is properly castable
                cast_func(value)
            except Exception as e:
                click.echo(f"Invalid value for {key}: {e}")
                return

            # If the config already exists, update it
            if config:
                config.value = value
                click.echo(f"Updated {key} to {value}")
            else:
                # Otherwise, insert a new record
                config = SystemConfig(key=key, value=value, updated_by=None)
                db.session.add(config)
                click.echo(f"Added {key} = {value}")

            db.session.commit()

    @config_cli.command("delete")
    @click.argument("key")
    def delete_config(key):
        """Delete a configuration key from the database."""
        with app.app_context():
            key = key.upper()
            config = SystemConfig.query.filter_by(key=key).first()
            if config:
                db.session.delete(config)
                db.session.commit()
                click.echo(f"Deleted config key: {key}")
            else:
                click.echo(f"No config key found: {key}")
