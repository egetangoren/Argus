"""
Argus Recon Framework - Module Package

Centralized imports for all reconnaissance modules.
Each module exposes a class with a consistent `run()` interface
that accepts a target and returns structured results as a dictionary.
"""

from modules.whois_lookup import WhoisLookup
from modules.dns_enum import DNSEnumerator
from modules.subdomain_enum import SubdomainEnumerator
from modules.port_scanner import PortScanner
from modules.banner_grabber import BannerGrabber
from modules.http_probe import HTTPProbe

__all__ = [
    "WhoisLookup",
    "DNSEnumerator",
    "SubdomainEnumerator",
    "PortScanner",
    "BannerGrabber",
    "HTTPProbe",
]
