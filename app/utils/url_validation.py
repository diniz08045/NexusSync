"""
URL validation module for secure handling of URLs in Flask applications.

This module provides functions for validating URLs, preventing SSRF attacks,
domain whitelisting, and safe redirections.
"""

import re
import ipaddress
import socket
import urllib.parse
from typing import Set, List, Optional, Dict, Any, Union, Callable
import logging

from flask import redirect, abort, current_app, request, url_for, Response

# Setup the URL validation logger
url_logger = logging.getLogger("app.url_validation")
url_logger.setLevel(logging.INFO)

# Allowed URL schemes (protocols)
ALLOWED_SCHEMES: Set[str] = {'http', 'https'}

# Dangerous local hostnames to prevent SSRF
DANGEROUS_HOSTNAMES: Set[str] = {
    'localhost', 'local', 'intranet', 'internal',
    'private', 'corp', 'server', 'admin', 'dev'
}

# IP ranges that should be blocked (RFC 1918 private addresses and more)
BLOCKED_IP_RANGES: List[str] = [
    '10.0.0.0/8',      # Private network
    '172.16.0.0/12',   # Private network
    '192.168.0.0/16',  # Private network
    '127.0.0.0/8',     # Localhost
    '169.254.0.0/16',  # Link-local
    '192.0.2.0/24',    # TEST-NET-1
    '198.51.100.0/24', # TEST-NET-2
    '203.0.113.0/24',  # TEST-NET-3
    '224.0.0.0/4',     # Multicast
    '240.0.0.0/4',     # Reserved for future use
    '100.64.0.0/10',   # Shared Address Space
    '0.0.0.0/8',       # Current network
]

# Parse blocked IP ranges into network objects for efficient checking
blocked_networks = [ipaddress.ip_network(cidr) for cidr in BLOCKED_IP_RANGES]

# Domain whitelist (default empty, should be configured in app initialization)
ALLOWED_DOMAINS: Set[str] = set()

def set_allowed_domains(domains: List[str]) -> None:
    """
    Set the list of allowed domains for URL validation.
    
    Args:
        domains: List of allowed domain names
    """
    global ALLOWED_DOMAINS
    # Filter out None values and convert to set
    if domains:
        filtered_domains = [d for d in domains if d]
        ALLOWED_DOMAINS = set(filtered_domains)
        if filtered_domains:
            url_logger.info(f"Allowed domains set: {', '.join(filtered_domains)}")
        else:
            url_logger.info("No allowed domains set (empty list)")
    else:
        ALLOWED_DOMAINS = set()
        url_logger.info("No allowed domains set (None provided)")

def is_ip_private(ip_str: str) -> bool:
    """
    Check if an IP address is private or reserved.
    
    Args:
        ip_str: The IP address as a string
        
    Returns:
        bool: True if the IP is private, False otherwise
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        
        # Check if the IP falls within any blocked network
        for network in blocked_networks:
            if ip in network:
                return True
                
        return False
    except ValueError:
        # If the input is not a valid IP address
        return False

def is_domain_dangerous(hostname: str) -> bool:
    """
    Check if a hostname appears to be dangerous (localhost, internal, etc.).
    
    Args:
        hostname: The hostname to check
        
    Returns:
        bool: True if the hostname appears dangerous, False otherwise
    """
    # Convert to lowercase for case-insensitive comparison
    hostname_lower = hostname.lower()
    
    # Check against dangerous hostname list
    for dangerous in DANGEROUS_HOSTNAMES:
        if dangerous in hostname_lower:
            return True
            
    # Check for IP-like hostnames with periods
    if re.match(r"^[\d\.]+$", hostname):
        return True
        
    return False

def resolve_hostname_to_ip(hostname: str) -> Optional[str]:
    """
    Resolve a hostname to an IP address.
    
    Args:
        hostname: The hostname to resolve
        
    Returns:
        Optional[str]: The resolved IP address, or None if resolution fails
    """
    try:
        ip = socket.gethostbyname(hostname)
        return ip
    except socket.gaierror:
        url_logger.warning(f"Could not resolve hostname: {hostname}")
        return None

def is_url_safe(url: str, enforce_whitelist: bool = True) -> bool:
    """
    Check if a URL is safe based on its scheme, host, and resolved IP.
    
    Args:
        url: The URL to check
        enforce_whitelist: Whether to enforce the domain whitelist
        
    Returns:
        bool: True if the URL is safe, False otherwise
    """
    if not url:
        return False
        
    # Parse the URL
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as e:
        url_logger.warning(f"URL parsing error: {str(e)}")
        return False
        
    # Check scheme
    if parsed.scheme and parsed.scheme not in ALLOWED_SCHEMES:
        url_logger.warning(f"URL has disallowed scheme: {url}")
        return False
        
    # If there's no netloc (e.g., relative URL), it's generally safe
    if not parsed.netloc:
        return True
        
    # Split netloc into host and port
    host = parsed.netloc
    if ':' in host:
        host = host.split(':', 1)[0]
        
    # Check if hostname appears dangerous
    if is_domain_dangerous(host):
        url_logger.warning(f"URL has dangerous hostname: {url}")
        return False
        
    # Enforce domain whitelist if configured
    if enforce_whitelist and ALLOWED_DOMAINS and host not in ALLOWED_DOMAINS:
        url_logger.warning(f"URL host not in whitelist: {url}")
        return False
        
    # Try to resolve the hostname to an IP
    ip = resolve_hostname_to_ip(host)
    if ip and is_ip_private(ip):
        url_logger.warning(f"URL resolves to private IP: {url} -> {ip}")
        return False
        
    return True

def safe_redirect_url(url: str, default_url: str = '/') -> str:
    """
    Ensure a redirect URL is safe, or fall back to a default URL.
    
    Args:
        url: The URL to redirect to
        default_url: The default URL to use if the requested URL is unsafe
        
    Returns:
        str: The safe URL to redirect to
    """
    if url and is_url_safe(url, enforce_whitelist=False):
        return url
    else:
        url_logger.warning(f"Unsafe redirect URL: {url}, using default: {default_url}")
        return default_url

def safe_redirect(url: str, default_url: str = '/') -> Response:
    """
    Safely perform a redirect after validating the URL.
    
    Args:
        url: The URL to redirect to
        default_url: The default URL to use if the requested URL is unsafe
        
    Returns:
        Response: A redirect response to a safe URL
    """
    safe_url = safe_redirect_url(url, default_url)
    return redirect(safe_url)

def validate_next_param() -> str:
    """
    Validate the 'next' parameter often used in login redirects.
    
    Returns:
        str: A safe URL to redirect to
    """
    next_url = request.args.get('next')
    return safe_redirect_url(next_url)

def external_url_required(func: Callable) -> Callable:
    """
    Decorator to require a valid external URL for a route parameter.
    
    Args:
        func: The function to decorate
        
    Returns:
        Callable: The decorated function
    """
    def decorated_function(*args, **kwargs):
        url = request.args.get('url')
        if not url or not is_url_safe(url, enforce_whitelist=True):
            url_logger.warning(f"Invalid external URL: {url}")
            abort(400, "Invalid or unsafe URL provided")
        return func(*args, **kwargs)
    return decorated_function