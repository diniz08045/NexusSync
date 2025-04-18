# app/security/intelligence/blocklist.py

from datetime import datetime
from typing import Dict, List

from flask import Blueprint, jsonify, request

# Import predefined risk thresholds
from .constants import RISK_THRESHOLD_HIGH, RISK_THRESHOLD_MEDIUM, RISK_THRESHOLD_LOW

# Import correlation engine to analyze IP-based threat data
from .correlation import correlation_engine

# Register the blocklist blueprint
bp_blocklist = Blueprint("blocklist", __name__)


# ============================================
# Class: BlocklistRule
# ============================================
class BlocklistRule:
    """
    Defines a rule for evaluating IP behavior and assigning a mitigation action.
    Each rule consists of multiple conditions (field/operator/value).
    """

    def __init__(self, name: str, conditions: List[Dict], action: str, priority: int = 1):
        self.name = name
        self.conditions = conditions  # A list of dictionaries: {"field", "operator", "value"}
        self.action = action  # Example: block, rate_limit, monitor
        self.priority = priority  # Lower numbers have higher priority
        self.created_at = datetime.utcnow()

    def to_dict(self) -> Dict:
        """Convert rule data to dictionary (for JSON serialization)."""
        return {
            "name": self.name,
            "conditions": self.conditions,
            "action": self.action,
            "priority": self.priority,
            "created_at": self.created_at.isoformat(),
        }

    def evaluate(self, ip_data: Dict) -> bool:
        """
        Evaluate the rule against a dictionary of IP correlation data.
        All conditions must pass for the rule to match.
        """
        for condition in self.conditions:
            field = condition.get("field")
            operator = condition.get("operator")
            value = condition.get("value")

            if field not in ip_data:
                return False
            ip_value = ip_data[field]

            # Evaluate condition using specified operator
            if operator == "eq" and ip_value != value:
                return False
            elif operator == "ne" and ip_value == value:
                return False
            elif operator == "gt" and ip_value <= value:
                return False
            elif operator == "lt" and ip_value >= value:
                return False
            elif operator == "ge" and ip_value < value:
                return False
            elif operator == "le" and ip_value > value:
                return False
            elif operator == "in" and ip_value not in value:
                return False
            elif operator == "contains" and value not in ip_value:
                return False

        return True


# ============================================
# Class: BlocklistRulesEngine
# ============================================
class BlocklistRulesEngine:
    """
    Rule engine to evaluate threat intelligence data and return actions like:
    block, rate_limit, monitor, etc.
    """

    def __init__(self):
        self.rules = []
        self._load_default_rules()

    def _load_default_rules(self):
        """
        Initialize engine with a few basic rules based on correlation_score.
        """
        self.rules = [
            BlocklistRule(
                name="High Risk Multiple Sources",
                conditions=[
                    {"field": "correlation_score", "operator": "ge", "value": RISK_THRESHOLD_HIGH},
                    {"field": "source_count", "operator": "ge", "value": 2},
                ],
                action="block",
                priority=1,
            ),
            BlocklistRule(
                name="Medium Risk Rate Limiting",
                conditions=[
                    {"field": "correlation_score", "operator": "ge", "value": RISK_THRESHOLD_MEDIUM},
                    {"field": "correlation_score", "operator": "lt", "value": RISK_THRESHOLD_HIGH},
                ],
                action="rate_limit",
                priority=2,
            ),
            BlocklistRule(
                name="Low Risk Monitoring",
                conditions=[
                    {"field": "correlation_score", "operator": "ge", "value": RISK_THRESHOLD_LOW},
                    {"field": "correlation_score", "operator": "lt", "value": RISK_THRESHOLD_MEDIUM},
                ],
                action="monitor",
                priority=3,
            ),
        ]

    def add_rule(self, rule: BlocklistRule) -> bool:
        """Add a new rule and sort the list by priority."""
        self.rules.append(rule)
        self.rules.sort(key=lambda r: r.priority)
        return True

    def remove_rule(self, rule_name: str) -> bool:
        """Remove a rule by name."""
        initial_count = len(self.rules)
        self.rules = [r for r in self.rules if r.name != rule_name]
        return len(self.rules) < initial_count

    def evaluate_ip(self, ip_address: str) -> Dict:
        """
        Evaluate all rules for a given IP using its correlation data.
        Returns the first matching rule and its action.
        """
        correlation_data = correlation_engine.correlate_ip(ip_address)
        default_action = {
            "action": "none",
            "matched_rule": None,
            "correlation_data": correlation_data,
        }
        for rule in self.rules:
            if rule.evaluate(correlation_data):
                return {
                    "action": rule.action,
                    "matched_rule": rule.name,
                    "correlation_data": correlation_data,
                }
        return default_action

    def get_rules(self) -> List[Dict]:
        """Return all rules in dictionary format for JSON display."""
        return [rule.to_dict() for rule in self.rules]


# Instantiate the rule engine globally
rules_engine = BlocklistRulesEngine()


# ============================================
# API Endpoints
# ============================================

@bp_blocklist.route("/evaluate/<ip_address>", methods=["GET"])
def evaluate_ip(ip_address):
    """Evaluate an IP and return the rule action applied to it."""
    result = rules_engine.evaluate_ip(ip_address)
    result["requested_at"] = datetime.utcnow().isoformat()
    return jsonify(result)


@bp_blocklist.route("/rules", methods=["GET"])
def get_rules():
    """Return a list of all blocklist rules."""
    rules = rules_engine.get_rules()
    return jsonify({"rules": rules, "requested_at": datetime.utcnow().isoformat()})


@bp_blocklist.route("/rules", methods=["POST"])
def add_rule():
    """Add a new rule to the blocklist engine."""
    data = request.get_json()
    rule = BlocklistRule(
        name=data.get("name"),
        conditions=data.get("conditions"),
        action=data.get("action"),
        priority=data.get("priority", 1),
    )
    success = rules_engine.add_rule(rule)
    return jsonify({
        "success": success,
        "rule": rule.to_dict(),
        "requested_at": datetime.utcnow().isoformat(),
    })


@bp_blocklist.route("/rules/<rule_name>", methods=["DELETE"])
def delete_rule(rule_name):
    """Remove a rule from the engine by name."""
    success = rules_engine.remove_rule(rule_name)
    return jsonify({
        "success": success,
        "rule_name": rule_name,
        "requested_at": datetime.utcnow().isoformat(),
    })
