# app/security/intelligence/scanning.py

import socket
from datetime import datetime, timedelta
from typing import Dict, List

from flask import Blueprint, current_app, jsonify, request
from sqlalchemy.exc import SQLAlchemyError

from app.models import HoneypotEvent, ThreatIntelEntry
from app.extensions import db

# Blueprint for scanning-related endpoints
bp_scanning = Blueprint("scanning", __name__)


class PortScanner:
    """
    Performs TCP port scans on common service ports.
    """

    def __init__(self):
        # Commonly targeted ports (e.g., HTTP, SSH, FTP, RDP, etc.)
        self.common_ports = [
            21, 22, 23, 25, 53, 80, 110, 143,
            443, 465, 587, 993, 995, 3306,
            3389, 5900, 8080,
        ]
        self.scan_timeout = 2  # Timeout in seconds for each port probe

    def scan_ip(self, ip_address: str, ports: List[int] = None) -> Dict:
        """
        Scans the specified IP for open ports.
        Returns open and scanned ports with a timestamp.
        """
        if ports is None:
            ports = self.common_ports

        results = {}
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.scan_timeout)
                result = sock.connect_ex((ip_address, port))
                results[port] = (result == 0)  # True if port is open
                sock.close()
            except socket.error:
                results[port] = False

        return {
            "ip_address": ip_address,
            "timestamp": datetime.utcnow().isoformat(),
            "open_ports": [port for port, is_open in results.items() if is_open],
            "scanned_ports": ports,
        }


class HoneypotMonitor:
    """
    Records honeypot events and correlates them with potential threat data.
    """

    def __init__(self):
        self.honeypot_events = {}

    def record_event(self, ip_address: str, event_type: str, details: Dict = None):
        """
        Logs honeypot events to the database.
        If the event type is serious (e.g., injection attacks), it is also
        recorded in the threat intelligence system.
        """
        if details is None:
            details = {}

        try:
            # Create and store honeypot event
            event = HoneypotEvent(
                ip_address=ip_address,
                event_type=event_type,
                details=details,
                created_at=datetime.utcnow(),
            )
            db.session.add(event)
            db.session.commit()

            current_app.logger.info(
                f"Recorded honeypot event from {ip_address}: {event_type}"
            )

            # Add threat intel entry for high-risk attack types
            if event_type in ["sql_injection", "xss_attempt", "path_traversal", "command_injection"]:
                entry = ThreatIntelEntry(
                    ip_address=ip_address,
                    source="Internal Honeypot",
                    threat_type=f"honeypot_{event_type}",
                    confidence_score=90,
                    metadata=details,
                    created_at=datetime.utcnow(),
                )
                db.session.add(entry)
                db.session.commit()

            return True
        except SQLAlchemyError as e:
            db.session.rollback()
            current_app.logger.error(f"Error recording honeypot event: {str(e)}")
            return False

    def get_recent_events(self, hours: int = 24) -> List[Dict]:
        """
        Retrieves honeypot events that occurred within the past N hours.
        """
        try:
            recent_time = datetime.utcnow() - timedelta(hours=hours)
            events = HoneypotEvent.query.filter(
                HoneypotEvent.created_at >= recent_time
            ).all()
            return [event.to_dict() for event in events]
        except SQLAlchemyError as e:
            current_app.logger.error(f"Error retrieving honeypot events: {str(e)}")
            return []


class EarlyWarningSystem:
    """
    Combines multiple intelligence sources (port scanning, honeypot logs,
    threat DB) to calculate a risk score for a given IP.
    """

    def __init__(self):
        self.port_scanner = PortScanner()
        self.honeypot_monitor = HoneypotMonitor()
        self.alerts = []

    def analyze_ip(self, ip_address: str) -> Dict:
        """
        Runs a threat analysis for the given IP.
        Calculates a composite risk score based on:
          - Open ports (risk of scanning exposure)
          - Honeypot events (active exploit attempts)
          - Threat database entries (known malicious activity)
        """
        # Run port scan
        scan_results = self.port_scanner.scan_ip(ip_address)

        # Get honeypot and threat data for the past 7 days
        honeypot_events = (
            HoneypotEvent.query.filter_by(ip_address=ip_address)
            .filter(HoneypotEvent.created_at >= datetime.utcnow() - timedelta(days=7))
            .all()
        )
        threat_entries = ThreatIntelEntry.query.filter_by(ip_address=ip_address).all()

        # Weighted risk components
        port_risk = len(scan_results.get("open_ports", [])) / len(scan_results.get("scanned_ports", [1]))
        honeypot_risk = len(honeypot_events) * 0.2
        threat_risk = len(threat_entries) * 0.15

        # Compute final risk score (bounded at 100)
        risk_score = min(100, int((port_risk * 30 + honeypot_risk * 40 + threat_risk * 30)))
        alert_threshold = 70

        # If risk is high, generate an alert
        if risk_score >= alert_threshold:
            alert = {
                "ip_address": ip_address,
                "risk_score": risk_score,
                "timestamp": datetime.utcnow().isoformat(),
                "reason": f"High risk score ({risk_score}) detected",
            }
            self.alerts.append(alert)

        return {
            "ip_address": ip_address,
            "risk_score": risk_score,
            "scan_results": scan_results,
            "honeypot_events": [event.to_dict() for event in honeypot_events],
            "threat_entries": [entry.to_dict() for entry in threat_entries],
            "is_high_risk": risk_score >= alert_threshold,
        }

    def get_recent_alerts(self, limit: int = 100) -> List[Dict]:
        """
        Returns recent alerts, sorted by timestamp.
        """
        return sorted(self.alerts, key=lambda a: a["timestamp"], reverse=True)[:limit]


# Global instances used by other parts of the app
port_scanner = PortScanner()
honeypot_monitor = HoneypotMonitor()
early_warning_system = EarlyWarningSystem()


# =======================
#        ROUTES
# =======================

@bp_scanning.route("/scan/<ip_address>", methods=["GET"])
def scan_ip_route(ip_address):
    """
    API endpoint to scan an IP for open ports.
    """
    results = port_scanner.scan_ip(ip_address)
    return jsonify(results)


@bp_scanning.route("/honeypot/events", methods=["GET"])
def get_honeypot_events_route():
    """
    API endpoint to retrieve recent honeypot events.
    Accepts optional 'hours' query parameter.
    """
    hours = request.args.get("hours", 24, type=int)
    events = honeypot_monitor.get_recent_events(hours=hours)
    return jsonify({"events": events, "requested_at": datetime.utcnow().isoformat()})


@bp_scanning.route("/early-warning/<ip_address>", methods=["GET"])
def early_warning_route(ip_address):
    """
    API endpoint to perform a full threat analysis on a given IP.
    Returns a risk score and relevant logs.
    """
    result = early_warning_system.analyze_ip(ip_address)
    result["requested_at"] = datetime.utcnow().isoformat()
    return jsonify(result)
