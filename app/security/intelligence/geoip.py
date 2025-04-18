from typing import Dict
import geoip2.database

class GeoIPManager:
    """
    GeoIPManager handles IP geolocation and ASN (Autonomous System Number) lookups.
    It supports multiple MaxMind databases:
    - City database (GeoLite2-City.mmdb)
    - ASN database (GeoLite2-ASN.mmdb)
    - Country database (GeoLite2-Country.mmdb)

    It can also flag high-risk countries based on predefined ISO codes.
    """

    def __init__(self):
        self.db_path = None  # Path to the GeoLite2-City.mmdb file
        self.reader = None  # City-level reader
        self.asn_reader = None  # ASN-level reader
        self.country_reader = None  # Country-level reader
        self.high_risk_countries = {"CN", "RU", "KP", "IR", "VE"}  # ISO codes for high-risk countries

    def init_app(self, app):
        """
        Initializes the GeoIP readers from the application's config.
        Expected config keys:
            - GEOIP_DB_PATH (City database)
            - GEOIP_ASN_DB_PATH (ASN database)
            - GEOIP_COUNTRY_DB_PATH (Country database)
        """
        self.db_path = app.config.get("GEOIP_DB_PATH")
        asn_db_path = app.config.get("GEOIP_ASN_DB_PATH")
        country_db_path = app.config.get("GEOIP_COUNTRY_DB_PATH")

        if self.db_path:
            try:
                self.reader = geoip2.database.Reader(self.db_path)
                app.logger.info(f"Initialized GeoIP (City) database from {self.db_path}")
            except Exception as e:
                app.logger.error(f"Failed to initialize GeoIP (City) database: {str(e)}")

        if asn_db_path:
            try:
                self.asn_reader = geoip2.database.Reader(asn_db_path)
                app.logger.info(f"Initialized ASN database from {asn_db_path}")
            except Exception as e:
                app.logger.error(f"Failed to initialize ASN database: {str(e)}")

        if country_db_path:
            try:
                self.country_reader = geoip2.database.Reader(country_db_path)
                app.logger.info(f"Initialized GeoIP (Country) database from {country_db_path}")
            except Exception as e:
                app.logger.error(f"Failed to initialize GeoIP (Country) database: {str(e)}")

    def get_ip_location(self, ip_address: str) -> Dict:
        """
        Returns location information for the given IP address.
        Tries city-level lookup first, then falls back to country-level.

        Response dictionary includes:
            - country_code, country_name, city (if available)
            - latitude, longitude (if available)
            - is_high_risk (based on hardcoded countries)
        """
        if self.reader:
            try:
                response = self.reader.city(ip_address)
                return {
                    "ip_address": ip_address,
                    "country_code": response.country.iso_code,
                    "country_name": response.country.name,
                    "city": response.city.name,
                    "latitude": response.location.latitude,
                    "longitude": response.location.longitude,
                    "is_high_risk": response.country.iso_code in self.high_risk_countries,
                }
            except Exception as e:
                self.logger_error(ip_address, "City lookup error", e)

        if self.country_reader:
            try:
                response = self.country_reader.country(ip_address)
                return {
                    "ip_address": ip_address,
                    "country_code": response.country.iso_code,
                    "country_name": response.country.name,
                    "city": None,
                    "latitude": None,
                    "longitude": None,
                    "is_high_risk": response.country.iso_code in self.high_risk_countries,
                }
            except Exception as e:
                return {"ip_address": ip_address, "error": str(e)}

        return {"ip_address": ip_address, "error": "GeoIP database not initialized"}

    def get_ip_asn(self, ip_address: str) -> Dict:
        """
        Returns ASN (Autonomous System Number) and organization for the given IP address.

        Example output:
        {
            "ip_address": "8.8.8.8",
            "asn": 15169,
            "asn_org": "Google LLC"
        }
        """
        if not self.asn_reader:
            return {"ip_address": ip_address, "error": "ASN database not initialized"}

        try:
            response = self.asn_reader.asn(ip_address)
            return {
                "ip_address": ip_address,
                "asn": response.autonomous_system_number,
                "asn_org": response.autonomous_system_organization,
            }
        except Exception as e:
            return {"ip_address": ip_address, "error": str(e)}

    def logger_error(self, ip_address: str, message: str, e: Exception):
        """
        Simple error logger for fallback debugging (outside Flask context).
        In production, replace with current_app.logger.error if available.
        """
        print(f"Error for {ip_address}: {message}: {str(e)}")


# Create a globally accessible instance
geoip_manager = GeoIPManager()
