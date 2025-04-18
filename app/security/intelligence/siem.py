# app/security/intelligence/siem.py

import json
from datetime import datetime
from flask import Blueprint, jsonify, request

# Blueprint for SIEM integration routes
bp_siem = Blueprint("siem", __name__)


class SIEMConnector:
    """
    SIEMConnector is responsible for formatting security events
    into various industry-standard formats for integration with
    external SIEM (Security Information and Event Management) systems.

    Supported formats:
        - JSON (default)
        - CEF (Common Event Format)
        - LEEF (Log Event Extended Format)
        - Syslog
    """

    def __init__(self):
        self.formats = ["cef", "leef", "json", "syslog"]
        self.default_format = "json"
        self.siem_endpoints = {}  # Optional future use for actual transmission

    def init_app(self, app):
        """
        Initializes the connector with SIEM endpoints from app config.
        """
        self.siem_endpoints = app.config.get("SIEM_ENDPOINTS", {})

    def format_event(self, event_type: str, data: dict, format_type: str = None) -> str:
        """
        Converts an event into the specified SIEM-compatible format.

        Args:
            event_type: A string indicating the event type (e.g. 'threat_alert')
            data: A dictionary of event details (e.g. IP, risk level, etc.)
            format_type: Desired format. Defaults to 'json' if not provided or invalid.

        Returns:
            A formatted string representing the event.
        """
        if format_type is None or format_type not in self.formats:
            format_type = self.default_format

        timestamp = datetime.utcnow().isoformat()

        if format_type == "json":
            # Standard JSON structure
            return json.dumps({
                "timestamp": timestamp,
                "event_type": event_type,
                "data": data
            })

        elif format_type == "cef":
            # CEF: Common Event Format (used by ArcSight and others)
            return (
                f"CEF:0|SuperAdminPortal|ThreatIntelHub|1.0|{event_type}|{data.get('ip_address', 'unknown')}|{data.get('risk_level', 0)}|"
                + "".join([f" {k}={v}" for k, v in data.items()])
            )

        elif format_type == "leef":
            # LEEF: Log Event Extended Format (used by QRadar)
            return (
                f"LEEF:1.0|SuperAdminPortal|ThreatIntelHub|1.0|{event_type}|"
                + "".join([f"\t{k}={v}" for k, v in data.items()])
            )

        elif format_type == "syslog":
            # Syslog format (used in general logging pipelines)
            return (
                f"<{self._get_syslog_priority(data.get('risk_level', 0))}>ThreatIntelHub: {event_type} - "
                + ", ".join([f"{k}={v}" for k, v in data.items()])
            )

    def _get_syslog_priority(self, risk_level: int) -> int:
        """
        Maps a risk level to a syslog priority value.

        Lower numbers = higher severity.
        """
        if risk_level >= 85:
            return 2  # Critical
        elif risk_level >= 60:
            return 4  # Warning
        elif risk_level >= 30:
            return 6  # Informational
        else:
            return 7  # Debug/Low


# ========================
#        API ROUTES
# ========================

@bp_siem.route("/format", methods=["GET"])
def siem_format():
    """
    API endpoint to preview the formatted SIEM-compatible string
    for a sample or provided event.

    Query Parameters:
        - event_type: The type of the event (e.g., 'scan_detected')
        - format: Desired format ('json', 'cef', 'leef', 'syslog')
        - ip_address: The IP address involved in the event
        - risk_level: Integer risk score for the event

    Returns:
        A JSON object containing the formatted event string.
    """
    event_type = request.args.get("event_type", "default_event")
    format_type = request.args.get("format", "json")

    data = {
        "ip_address": request.args.get("ip_address", "1.2.3.4"),
        "risk_level": int(request.args.get("risk_level", 50)),
    }

    siem_connector = SIEMConnector()
    formatted_event = siem_connector.format_event(
        event_type, data, format_type=format_type
    )

    return jsonify({
        "formatted_event": formatted_event,
        "requested_at": datetime.utcnow().isoformat(),
    })
