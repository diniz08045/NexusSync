from datetime import datetime
from flask import Blueprint, jsonify

# GeoIP manager handles IP-to-location and ASN lookups
from app.security.intelligence.geoip import geoip_manager

# Define a blueprint for all GeoIP-related API routes
bp_geoip_api = Blueprint("geoip_api", __name__, url_prefix="/geoip")


# -------------------------------
# Route: Get Full GeoIP Info
# -------------------------------
@bp_geoip_api.route("/<ip_address>", methods=["GET"])
def get_geoip(ip_address):
    """
    Returns location data for a given IP address (e.g., city, region, country).
    """
    result = geoip_manager.get_ip_location(ip_address)
    result["requested_at"] = datetime.utcnow().isoformat()  # Add timestamp
    return jsonify(result)


# -------------------------------
# Route: Get ASN (Autonomous System Number) Info
# -------------------------------
@bp_geoip_api.route("/asn/<ip_address>", methods=["GET"])
def get_asn(ip_address):
    """
    Returns ASN info for a given IP address.
    ASN = Internet Service Provider / organization ownership data.
    """
    result = geoip_manager.get_ip_asn(ip_address)
    result["requested_at"] = datetime.utcnow().isoformat()
    return jsonify(result)


# -------------------------------
# Route: Get Blocked Countries List
# -------------------------------
@bp_geoip_api.route("/blocked/countries", methods=["GET"])
def blocked_countries():
    """
    Returns a list of country codes that are currently blocked by the system.
    """
    result = geoip_manager.get_blocked_countries()
    return jsonify({
        "blocked_countries": result,
        "requested_at": datetime.utcnow().isoformat()
    })


# -------------------------------
# Route: Get Blocked ASNs List
# -------------------------------
@bp_geoip_api.route("/blocked/asns", methods=["GET"])
def blocked_asns():
    """
    Returns a list of blocked ASNs (Internet providers or networks).
    """
    result = geoip_manager.get_blocked_asns()
    return jsonify({
        "blocked_asns": result,
        "requested_at": datetime.utcnow().isoformat()
    })


# -------------------------------
# Route: Get Country Name & Code by IP
# -------------------------------
@bp_geoip_api.route("/country/<ip_address>", methods=["GET"])
def get_country(ip_address):
    """
    Returns country name and ISO code for a given IP.
    Handles GeoIP country lookup with fallback for uninitialized DB or errors.
    """
    if geoip_manager.country_reader:
        try:
            response = geoip_manager.country_reader.country(ip_address)
            result = {
                "ip_address": ip_address,
                "country_code": response.country.iso_code,
                "country_name": response.country.name,
            }
        except Exception as e:
            result = {"ip_address": ip_address, "error": str(e)}
    else:
        # Country DB is not initialized
        result = {
            "ip_address": ip_address,
            "error": "Country database not initialized"
        }

    result["requested_at"] = datetime.utcnow().isoformat()
    return jsonify(result)
