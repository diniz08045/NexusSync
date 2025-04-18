from datetime import datetime
import requests
from flask import Blueprint, current_app, jsonify
from sqlalchemy.exc import SQLAlchemyError

from app.models import ThreatIntelEntry
from .constants import RISK_THRESHOLD_HIGH, RISK_THRESHOLD_LOW, RISK_THRESHOLD_MEDIUM

# Blueprint for correlation routes
bp_correlation = Blueprint("correlation", __name__)

def fetch_abuseipdb_data(ip_address: str) -> dict:
    """
    Retrieves threat intelligence data for a given IP address from AbuseIPDB.

    Returns a dictionary containing:
        - confidence_score (0–100)
        - threat_type (e.g. 'abuse' or 'unknown')
        - source ('AbuseIPDB')

    Logs appropriate messages if the API key is missing or the request fails.
    """
    api_key = current_app.config.get("ABUSEIPDB_API_KEY")
    if not api_key:
        current_app.logger.error("ABUSEIPDB_API_KEY is not configured")
        return {}

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {"Accept": "application/json", "Key": api_key}
    params = {"ipAddress": ip_address, "maxAgeInDays": 90}

    try:
        current_app.logger.debug(f"Sending request to AbuseIPDB for IP: {ip_address}")
        response = requests.get(url, headers=headers, params=params, timeout=10)
        current_app.logger.debug(f"AbuseIPDB response status: {response.status_code}")
        response.raise_for_status()

        data = response.json()
        current_app.logger.debug(f"AbuseIPDB raw response: {data}")

        result = data.get("data", {})
        abuse_confidence = result.get("abuseConfidenceScore", 0)
        return {
            "source": "AbuseIPDB",
            "confidence_score": int(abuse_confidence),
            "threat_type": "abuse" if abuse_confidence > 50 else "unknown",
        }

    except requests.RequestException as e:
        current_app.logger.error(f"Request error for {ip_address}: {e}")
        return {}
    except ValueError as e:
        current_app.logger.error(f"JSON decode error for {ip_address}: {e}")
        return {}


class ThreatCorrelationEngine:
    """
    Correlates threat intelligence data from local and external sources to produce
    a threat score and actionable recommendation for a given IP address.
    """

    def __init__(self):
        # Defines the time window (in days) for which historical data is considered.
        self.correlation_window_days = 30

    def correlate_ip(self, ip_address: str) -> dict:
        """
        Aggregates and analyzes local DB entries and external intelligence (AbuseIPDB)
        to calculate a correlation score and return a threat assessment.

        Returns a dictionary with:
            - correlation score
            - list of sources
            - first/last seen timestamps
            - recommendation
        """
        try:
            current_app.logger.debug(f"Correlating IP: {ip_address}")

            # Fetch all threat entries for this IP from the local database.
            local_entries = ThreatIntelEntry.query.filter_by(ip_address=ip_address).all()
            current_app.logger.debug(f"Found {len(local_entries)} local entries.")

            # Fetch external threat intelligence from AbuseIPDB
            abuse_data = fetch_abuseipdb_data(ip_address)

            # If no threat data is found, return a default result
            if not local_entries and not abuse_data:
                current_app.logger.info(f"No threat data for {ip_address}")
                return {
                    "ip_address": ip_address,
                    "correlation_score": 0,
                    "sources": [],
                    "first_seen": None,
                    "last_seen": None,
                    "recommendation": "No threat data available",
                }

            # Initialize variables for aggregating threat metrics
            sources = set()
            confidence_scores = []
            threat_types = set()
            first_seen = None
            last_seen = None

            # Process local database entries
            if local_entries:
                first_seen = min(entry.created_at for entry in local_entries)
                last_seen = max(getattr(entry, "updated_at", entry.created_at) for entry in local_entries)
                for entry in local_entries:
                    sources.add(entry.source)
                    confidence_scores.append(entry.confidence_score)
                    threat_types.add(entry.threat_type)

            # Add data from AbuseIPDB if present
            if abuse_data:
                sources.add(abuse_data.get("source", "AbuseIPDB"))
                confidence_scores.append(abuse_data.get("confidence_score", 50))
                threat_types.add(abuse_data.get("threat_type", "unknown"))
                if not first_seen:
                    first_seen = datetime.utcnow()
                if not last_seen:
                    last_seen = datetime.utcnow()

            # Calculate how long this IP has been persistent in logs
            persistence_days = (datetime.utcnow() - first_seen).days if first_seen else 0

            # Normalize each contributing factor to the 0–1 range
            source_factor = min(len(sources) / 5, 1.0)
            confidence_factor = sum(confidence_scores) / (len(confidence_scores) * 100)
            persistence_factor = min(persistence_days / self.correlation_window_days, 1.0)

            # Final score is a weighted sum of source count, confidence level, and persistence
            correlation_score = int(
                (source_factor * 0.4 + confidence_factor * 0.4 + persistence_factor * 0.2) * 100
            )

            # Generate an action recommendation based on the score and threat characteristics
            recommendation = self._generate_recommendation(correlation_score, sources, threat_types)

            result = {
                "ip_address": ip_address,
                "correlation_score": correlation_score,
                "sources": list(sources),
                "source_count": len(sources),
                "threat_types": list(threat_types),
                "confidence_average": sum(confidence_scores) / len(confidence_scores),
                "first_seen": first_seen.isoformat() if first_seen else None,
                "last_seen": last_seen.isoformat() if last_seen else None,
                "persistence_days": persistence_days,
                "recommendation": recommendation,
            }

            current_app.logger.debug(f"Final correlation result: {result}")
            return result

        except SQLAlchemyError as e:
            current_app.logger.error(f"Database error: {e}")
            return {"ip_address": ip_address, "error": "Database error during correlation"}
        except Exception as e:
            current_app.logger.error(f"Unexpected error: {e}")
            return {"ip_address": ip_address, "error": "General error during correlation"}

    def _generate_recommendation(self, score: int, sources: set, threat_types: set) -> str:
        """
        Determines action recommendation based on the correlation score.
        """
        if score < RISK_THRESHOLD_LOW:
            return "Monitor: Low risk, continue monitoring"
        elif score < RISK_THRESHOLD_MEDIUM:
            return "Rate Limit: Medium risk, consider rate limiting"
        elif score < RISK_THRESHOLD_HIGH:
            return "Block: High risk, recommended for blocking"
        else:
            return "Immediate Block: Critical risk, immediate blocking recommended"


# Instantiate a global correlation engine object
correlation_engine = ThreatCorrelationEngine()


@bp_correlation.route("/correlate/<ip_address>", methods=["GET"])
def correlate_ip_route(ip_address):
    """
    Flask route to trigger threat correlation for the given IP address.
    Returns JSON with correlation results and timestamp.
    """
    result = correlation_engine.correlate_ip(ip_address)
    result["requested_at"] = datetime.utcnow().isoformat()
    return jsonify(result)
