from datetime import datetime
from flask import (
    jsonify, request,
    render_template, flash, redirect, url_for
)
from .blueprint import superadmin_bp
from .decorators import superadmin_required

# Security intelligence modules
from app.security.intelligence.geoip       import geoip_manager
from app.security.intelligence.correlation import correlation_engine
from app.security.intelligence.scanning    import port_scanner, honeypot_monitor
from app.security.intelligence.blocklist   import rules_engine
from app.security.intelligence.spamhaus    import fetch_spamhaus_drop_list
from app.security.intelligence.siem        import SIEMConnector
from app.security.intelligence.behavioral  import behavioral_analyzer


# ============================================
#              JSON API ENDPOINTS
# ============================================

@superadmin_bp.route("/api/security-intel/geoip/<ip_address>", methods=["GET"])
@superadmin_required
def api_geoip(ip_address):
    """
    Return GeoIP location data for the given IP address.
    """
    result = geoip_manager.get_ip_location(ip_address)
    result["requested_at"] = datetime.utcnow().isoformat()
    return jsonify(result)


@superadmin_bp.route("/api/security-intel/asn/<ip_address>", methods=["GET"])
@superadmin_required
def api_asn(ip_address):
    """
    Return ASN (Autonomous System Number) data for the given IP address.
    """
    result = geoip_manager.get_ip_asn(ip_address)
    result["requested_at"] = datetime.utcnow().isoformat()
    return jsonify(result)


@superadmin_bp.route("/api/security-intel/correlate/<ip_address>", methods=["GET"])
@superadmin_required
def api_correlate(ip_address):
    """
    Return correlation engine analysis for the given IP.
    Useful for identifying suspicious behavior patterns.
    """
    result = correlation_engine.correlate_ip(ip_address)
    result["requested_at"] = datetime.utcnow().isoformat()
    return jsonify(result)


@superadmin_bp.route("/api/security-intel/scan/<ip_address>", methods=["GET"])
@superadmin_required
def api_scan(ip_address):
    """
    Return scan result for the given IP using the internal port scanner.
    """
    result = port_scanner.scan_ip(ip_address)
    return jsonify(result)


@superadmin_bp.route("/api/security-intel/honeypot/events", methods=["GET"])
@superadmin_required
def api_honeypot():
    """
    Return recent honeypot events within the specified number of hours.
    """
    hours = request.args.get("hours", 24, type=int)
    events = honeypot_monitor.get_recent_events(hours=hours)
    return jsonify({"events": events, "requested_at": datetime.utcnow().isoformat()})


@superadmin_bp.route("/api/security-intel/blocklist/evaluate/<ip_address>", methods=["GET"])
@superadmin_required
def api_evaluate(ip_address):
    """
    Evaluate the given IP address using all available blocklist rules.
    """
    result = rules_engine.evaluate_ip(ip_address)
    result["requested_at"] = datetime.utcnow().isoformat()
    return jsonify(result)


@superadmin_bp.route("/api/security-intel/blocklist/rules", methods=["GET"])
@superadmin_required
def api_rules():
    """
    Return all currently configured blocklist rules.
    """
    rules = rules_engine.get_rules()
    return jsonify({"rules": rules, "requested_at": datetime.utcnow().isoformat()})


# ============================================
#            TEMPLATE-BASED VIEWS
# ============================================

@superadmin_bp.route("/security-intel/geoip", methods=["GET"], endpoint="security_intel_geoip")
@superadmin_required
def tpl_geoip():
    """
    Render GeoIP lookup page and result based on user input.
    """
    ip = request.args.get("ip", "")
    result = geoip_manager.get_ip_location(ip) if ip else None
    if result:
        result["requested_at"] = datetime.utcnow().isoformat()
    return render_template("superadmin/security_intel.html", tab="geoip", ip=ip, result=result)


@superadmin_bp.route("/security-intel/asn", methods=["GET"], endpoint="security_intel_asn")
@superadmin_required
def tpl_asn():
    """
    Render ASN lookup page.
    """
    ip = request.args.get("ip", "")
    result = geoip_manager.get_ip_asn(ip) if ip else None
    if result:
        result["requested_at"] = datetime.utcnow().isoformat()
    return render_template("superadmin/security_intel.html", tab="asn", ip=ip, result=result)


@superadmin_bp.route("/security-intel/correlate", methods=["GET"], endpoint="security_intel_correlation")
@superadmin_required
def tpl_correlate():
    """
    Render correlation analysis view.
    """
    ip = request.args.get("ip", "")
    result = correlation_engine.correlate_ip(ip) if ip else None
    if result:
        result["requested_at"] = datetime.utcnow().isoformat()
    return render_template("superadmin/security_intel.html", tab="correlate", ip=ip, result=result)


@superadmin_bp.route("/security-intel/scan", methods=["GET"], endpoint="security_intel_scan")
@superadmin_required
def tpl_scan():
    """
    Render scan result view for the given IP.
    """
    ip = request.args.get("ip", "")
    result = port_scanner.scan_ip(ip) if ip else None
    return render_template("superadmin/security_intel.html", tab="scan", ip=ip, result=result)


@superadmin_bp.route("/security-intel/honeypot", methods=["GET"], endpoint="security_intel_honeypot")
@superadmin_required
def tpl_honeypot():
    """
    Show recent honeypot activity over the last N hours.
    """
    hours = request.args.get("hours", 24, type=int)
    events = honeypot_monitor.get_recent_events(hours=hours)
    return render_template("superadmin/security_intel.html", tab="honeypot", result={"events": events})


@superadmin_bp.route("/security-intel/evaluate", methods=["GET"], endpoint="security_intel_evaluate")
@superadmin_required
def tpl_evaluate():
    """
    Show evaluation result of an IP address based on internal rules.
    """
    ip = request.args.get("ip", "")
    result = rules_engine.evaluate_ip(ip) if ip else None
    if result:
        result["requested_at"] = datetime.utcnow().isoformat()
    return render_template("superadmin/security_intel.html", tab="evaluate", ip=ip, result=result)


@superadmin_bp.route("/security-intel/drop", methods=["GET"], endpoint="security_intel_drop")
@superadmin_required
def tpl_drop():
    """
    Show the current Spamhaus DROP list (blocked IP networks).
    """
    drop_list = fetch_spamhaus_drop_list()
    return render_template("superadmin/security_intel.html", tab="drop", drop_list=drop_list)


@superadmin_bp.route("/security-intel/rules", methods=["GET"], endpoint="security_intel_rules")
@superadmin_required
def tpl_rules():
    """
    Display currently configured security rules used for evaluating threats.
    """
    rules = rules_engine.get_rules()
    return render_template("superadmin/security_intel.html", tab="rules", rules=rules)
