# app/security/intelligence/spamhaus.py

import ipaddress
from datetime import datetime
import requests
from flask import Blueprint, current_app, jsonify, request

from app.extensions import db
from app.models.blocked_ips import BlockedIPRange

# Blueprint for Spamhaus integration routes
bp_spamhaus = Blueprint("spamhaus", __name__)


def fetch_spamhaus_drop_list() -> list:
    """
    Fetches and parses the Spamhaus DROP list from the official source.

    Returns:
        A list of ipaddress.IPv4Network or IPv6Network objects representing banned IP ranges.
    """
    url = "https://www.spamhaus.org/drop/drop.lasso"
    drop_list = []

    try:
        current_app.logger.debug("Fetching Spamhaus DROP list from: %s", url)
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        current_app.logger.debug("Spamhaus DROP list fetched successfully")

        for line in response.text.splitlines():
            line = line.strip()

            # Skip comments and empty lines
            if not line or line.startswith("#") or line.startswith(";"):
                continue

            parts = line.split()
            network_str = parts[0]

            # Handle lines starting with semicolons defensively
            if network_str.startswith(";"):
                current_app.logger.debug("Skipping comment-style line: %s", line)
                continue

            try:
                network = ipaddress.ip_network(network_str)
                drop_list.append(network)
            except ValueError as ve:
                current_app.logger.error("Error parsing network '%s': %s", network_str, ve)

        current_app.logger.info("Loaded %d networks from Spamhaus DROP list.", len(drop_list))
        return drop_list

    except requests.RequestException as e:
        current_app.logger.error("Error fetching Spamhaus DROP list: %s", e)
        return []


@bp_spamhaus.route("/drop", methods=["GET"])
def get_spamhaus_drop():
    """
    API endpoint: Returns the list of IP ranges from the Spamhaus DROP list.
    
    Response:
        - drop_list: List of banned CIDR networks
        - total_networks: Count of entries
    """
    networks = fetch_spamhaus_drop_list()
    network_list = [str(net) for net in networks]
    return jsonify({"drop_list": network_list, "total_networks": len(network_list)})


def update_blocked_ip_ranges():
    """
    Syncs the current Spamhaus DROP list with the database.

    - Adds new IP ranges not already in the database
    - Updates the `updated_at` timestamp and marks them as 'auto' updated
    """
    current_app.logger.info("Starting update of Blocked IP Ranges from Spamhaus...")
    drop_networks = fetch_spamhaus_drop_list()

    for network in drop_networks:
        network_str = str(network)
        existing = BlockedIPRange.query.filter_by(network=network_str).first()
        if existing:
            existing.updated_at = datetime.utcnow()
            existing.updated_by = "auto"
        else:
            new_entry = BlockedIPRange(
                network=network_str,
                reason="Spamhaus DROP list",
                updated_by="auto"
            )
            db.session.add(new_entry)

    try:
        db.session.commit()
        current_app.logger.info("Blocked IP Ranges updated successfully.")
    except Exception as e:
        db.session.rollback()
        current_app.logger.error("Error updating Blocked IP Ranges: %s", e)


@bp_spamhaus.route("/db", methods=["GET"])
def get_blocked_ip_ranges():
    """
    API endpoint: Returns all blocked IP ranges currently stored in the database.
    
    Response:
        - blocked_ip_ranges: List of blocked ranges with metadata
        - total: Count of blocked entries
    """
    entries = BlockedIPRange.query.all()
    data = [entry.to_dict() for entry in entries]
    return jsonify({"blocked_ip_ranges": data, "total": len(data)})


@bp_spamhaus.route("/manual-ban", methods=["POST"])
def add_manual_ban():
    """
    API endpoint: Allows a user to manually ban a specific IP or CIDR range.

    Request JSON:
        {
            "ip": "1.2.3.4" or "1.2.3.0/24",
            "reason": "optional reason"
        }

    Behavior:
        - Converts IPs to CIDR form (/32 or /128)
        - Skips if already banned
        - Saves to DB and returns the new ban
    """
    data = request.get_json()
    if not data or "ip" not in data:
        return jsonify({"error": "Missing 'ip' in request body"}), 400

    ip_input = data["ip"]
    reason = data.get("reason", "Manual ban")

    try:
        # Attempt to parse as a full network first
        try:
            network = ipaddress.ip_network(ip_input, strict=False)
        except ValueError:
            # If it's a single IP, convert to /32 (IPv4) or /128 (IPv6)
            ip_obj = ipaddress.ip_address(ip_input)
            if ip_obj.version == 4:
                network = ipaddress.ip_network(f"{ip_obj}/32", strict=False)
            else:
                network = ipaddress.ip_network(f"{ip_obj}/128", strict=False)

        network_str = str(network)

        # Check if already banned
        existing = BlockedIPRange.query.filter_by(network=network_str).first()
        if existing:
            return jsonify({
                "message": f"Network {network_str} is already banned.",
                "network": existing.to_dict(),
            }), 200

        # Create new entry
        new_ban = BlockedIPRange(
            network=network_str,
            reason=reason,
            updated_by="manual"
        )
        db.session.add(new_ban)
        db.session.commit()

        current_app.logger.info(f"Manually banned {network_str} for reason: {reason}")
        return jsonify({
            "message": f"Network {network_str} banned successfully.",
            "network": new_ban.to_dict(),
        }), 201

    except Exception as e:
        current_app.logger.error(f"Error processing manual ban for {ip_input}: {e}")
        db.session.rollback()
        return jsonify({"error": f"Error processing manual ban: {e}"}), 500
