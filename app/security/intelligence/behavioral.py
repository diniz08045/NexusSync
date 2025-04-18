from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional

from flask import Blueprint, jsonify, request
from sqlalchemy.exc import SQLAlchemyError

from app.models import ThreatIntelEntry
from app.extensions import db

# Flask Blueprint for behavioral analysis endpoints
bp_behavior = Blueprint("behavior", __name__)


# ==========================================
# Class: BehavioralAnalyzer
# ==========================================
class BehavioralAnalyzer:
    """
    Tracks and analyzes request behavior by IP address.
    Flags suspicious activity such as brute force attempts, excessive requests,
    or endpoint probing, and optionally stores flagged IPs in the threat intel DB.
    """

    def __init__(self):
        self.ip_behaviors = {}  # Stores request history and stats by IP
        self.rate_limit_thresholds = {"normal": 100, "auth": 10, "admin": 20}

    def record_request(
        self,
        ip_address: str,
        endpoint: str,
        method: str,
        status_code: int,
        user_id: Optional[int] = None,
    ):
        """
        Logs a single HTTP request and updates stats for the given IP.
        Returns the result of behavior analysis.
        """
        timestamp = datetime.utcnow()

        # Initialize IP record if not tracked before
        if ip_address not in self.ip_behaviors:
            self.ip_behaviors[ip_address] = {
                "requests": [],
                "endpoints": defaultdict(int),
                "methods": defaultdict(int),
                "status_codes": defaultdict(int),
                "auth_attempts": 0,
                "admin_actions": 0,
                "first_seen": timestamp,
                "last_seen": timestamp,
                "user_ids": set(),
            }

        # Update tracked stats for this request
        behavior = self.ip_behaviors[ip_address]
        behavior["requests"].append(timestamp)
        behavior["endpoints"][endpoint] += 1
        behavior["methods"][method] += 1
        behavior["status_codes"][status_code] += 1
        behavior["last_seen"] = timestamp

        if user_id:
            behavior["user_ids"].add(user_id)
        if "/login" in endpoint or "/auth" in endpoint:
            behavior["auth_attempts"] += 1
        if "/admin" in endpoint or "/superadmin" in endpoint:
            behavior["admin_actions"] += 1

        # Keep only requests from the last hour
        one_hour_ago = timestamp - timedelta(hours=1)
        behavior["requests"] = [r for r in behavior["requests"] if r >= one_hour_ago]

        return self.analyze_behavior(ip_address)

    def analyze_behavior(self, ip_address: str) -> Dict:
        """
        Analyzes a given IP's behavior and returns a suspicion report.
        If highly suspicious, adds entry to ThreatIntelEntry DB.
        """
        if ip_address not in self.ip_behaviors:
            return {"ip_address": ip_address, "suspicious": False}

        behavior = self.ip_behaviors[ip_address]
        now = datetime.utcnow()
        recent_requests = [
            r for r in behavior["requests"] if r >= now - timedelta(minutes=1)
        ]
        request_rate = len(recent_requests)

        # Detection logic
        is_rate_exceeded = (
            request_rate > self.rate_limit_thresholds["normal"]
            or behavior["auth_attempts"] > self.rate_limit_thresholds["auth"]
            or behavior["admin_actions"] > self.rate_limit_thresholds["admin"]
        )
        is_distributed_users = len(behavior["user_ids"]) > 1 and request_rate > 30
        endpoint_diversity = len(behavior["endpoints"])
        is_unusual_diversity = endpoint_diversity > 20 and request_rate > 30

        # Calculate error rate from status codes
        error_count = sum(
            behavior["status_codes"].get(code, 0) for code in range(400, 600)
        )
        total_status = sum(behavior["status_codes"].values())
        error_rate = error_count / max(1, total_status)
        is_high_error_rate = error_rate > 0.3 and error_count > 10

        # Assign weighted scores to each anomaly type
        suspicion_factors = [
            is_rate_exceeded * 40,
            is_distributed_users * 30,
            is_unusual_diversity * 20,
            is_high_error_rate * 20,
        ]
        suspicion_score = min(100, sum(suspicion_factors))

        # Optional: persist high-risk IPs into the threat intel DB
        if suspicion_score >= 70:
            try:
                entry = ThreatIntelEntry(
                    ip_address=ip_address,
                    source="Behavioral Analysis",
                    threat_type="suspicious_behavior",
                    confidence_score=suspicion_score,
                    metadata={
                        "request_rate": request_rate,
                        "auth_attempts": behavior["auth_attempts"],
                        "admin_actions": behavior["admin_actions"],
                        "endpoint_diversity": endpoint_diversity,
                        "error_rate": error_rate,
                        "user_count": len(behavior["user_ids"]),
                    },
                    created_at=datetime.utcnow(),
                )
                db.session.add(entry)
                db.session.commit()
            except SQLAlchemyError:
                db.session.rollback()

        return {
            "ip_address": ip_address,
            "suspicious": suspicion_score >= 50,
            "suspicion_score": suspicion_score,
            "request_rate": request_rate,
            "auth_attempts": behavior["auth_attempts"],
            "admin_actions": behavior["admin_actions"],
            "endpoint_diversity": endpoint_diversity,
            "error_rate": error_rate,
            "user_count": len(behavior["user_ids"]),
            "recommendation": (
                "block"
                if suspicion_score >= 70
                else "rate_limit" if suspicion_score >= 50
                else "monitor"
            ),
        }

    def get_all_behaviors(self, min_suspicion: int = 0) -> List[Dict]:
        """
        Returns all IP behaviors that exceed the given suspicion score.
        Sorted descending by suspicion.
        """
        results = []
        for ip_address in self.ip_behaviors:
            analysis = self.analyze_behavior(ip_address)
            if analysis["suspicion_score"] >= min_suspicion:
                results.append(analysis)
        return sorted(results, key=lambda x: x["suspicion_score"], reverse=True)


# Instantiate global analyzer
behavioral_analyzer = BehavioralAnalyzer()


# ==========================================
# API Endpoints for Behavioral Intel
# ==========================================

@bp_behavior.route("/behavior/<ip_address>", methods=["GET"])
def behavior_analysis(ip_address):
    """
    Returns real-time behavioral analysis for a specific IP address.
    """
    result = behavioral_analyzer.analyze_behavior(ip_address)
    result["requested_at"] = datetime.utcnow().isoformat()
    return jsonify(result)


@bp_behavior.route("/behaviors", methods=["GET"])
def get_all_behaviors():
    """
    Returns all tracked IP behaviors that exceed a suspicion threshold.
    Accepts optional query param `min_suspicion`.
    """
    min_suspicion = request.args.get("min_suspicion", 0, type=int)
    results = behavioral_analyzer.get_all_behaviors(min_suspicion=min_suspicion)
    return jsonify({
        "behaviors": results,
        "requested_at": datetime.utcnow().isoformat()
    })
