"""
enricher.py - IP Threat Intelligence Enricher for Windows Event Analyzer

Enriches alerts that contain source IP addresses with geolocation,
organisation and ASN data from ipinfo.io.

Features:
  - In-memory cache - each IP looked up at most once per run
  - RFC 1918 / loopback / link-local skip - no wasted API calls
  - Optional token via IPINFO_TOKEN env var or .env file
  - Graceful degradation - pipeline continues without enrichment if
    no token is configured or API is unreachable
  - Tor exit node detection via org field

Usage:
    enricher = IPEnricher()
    alerts = enricher.enrich_alerts(alerts)
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import urllib.error
import urllib.request

from config.settings import IPINFO_BASE_URL as _IPINFO_BASE
from config.settings import IPINFO_REQUEST_TIMEOUT as _REQUEST_TIMEOUT

logger = logging.getLogger(__name__)

# Load token from environment (set via .env or shell)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

_TOKEN = os.environ.get("IPINFO_TOKEN", "")


class IPEnricher:
    """Enriches alert IP addresses with ipinfo.io threat intelligence"""

    def __init__(self, token: str = "") -> None:
        self._token = token or _TOKEN
        self._cache: dict[str, dict | None] = {}
        if not self._token:
            logger.info(
                "No IPINFO_TOKEN set - IP enrichment disabled. "
                "Set IPINFO_TOKEN in .env to enable."
            )

    def enrich_alerts(self, alerts: list[dict]) -> list[dict]:
        """Enrich all alerts that have a source IP address

        Adds an 'intel' key to each alert:
            {
                "country":  str | None,
                "org":      str | None,
                "asn":      str | None,
                "city":     str | None,
                "is_tor":   bool,
                "is_private": bool,
            }

        Args:
            alerts: Alert list from detector.run_all_detections()

        Returns:
            Same list with 'intel' key added to each alert
        """
        for alert in alerts:
            ip = alert.get("ip")
            alert["intel"] = self.get_ip_info(ip) if ip else _no_intel()
        return alerts

    def get_ip_info(self, ip: str) -> dict:
        """Look up a single IP address

        Args:
            ip: IPv4 or IPv6 address string

        Returns:
            Intel dict with country, org, asn, city, is_tor, is_private
        """
        if not ip:
            return _no_intel()

        if _is_private(ip):
            return {
                "country":    "PRIVATE",
                "org":        "Internal Network",
                "asn":        None,
                "city":       None,
                "is_tor":     False,
                "is_private": True,
            }

        if ip in self._cache:
            return self._cache[ip] or _no_intel()

        if not self._token:
            self._cache[ip] = None
            return _no_intel()

        result = self._query(ip)
        self._cache[ip] = result
        return result or _no_intel()

    def _query(self, ip: str) -> dict | None:
        """Query ipinfo.io for a single IP"""
        url = f"{_IPINFO_BASE}/{ip}/json?token={self._token}"
        try:
            req = urllib.request.Request(
                url,
                headers={"Accept": "application/json",
                         "User-Agent": "windows-event-analyzer/1.0"},
            )
            with urllib.request.urlopen(req, timeout=_REQUEST_TIMEOUT) as resp:
                data = json.loads(resp.read().decode())

            org = data.get("org", "")
            asn = org.split()[0] if org and org.startswith("AS") else None
            is_tor = "tor" in org.lower() if org else False

            return {
                "country":    data.get("country"),
                "org":        org or None,
                "asn":        asn,
                "city":       data.get("city"),
                "is_tor":     is_tor,
                "is_private": False,
            }
        except urllib.error.HTTPError as e:
            if e.code == 429:
                logger.warning("ipinfo.io rate limit hit for %s", ip)
            else:
                logger.debug("ipinfo.io HTTP error for %s: %s", ip, e)
            return None
        except urllib.error.URLError as e:
            logger.debug("ipinfo.io connection error for %s: %s", ip, e)
            return None
        except Exception as e:
            logger.debug("ipinfo.io unexpected error for %s: %s", ip, e)
            return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _no_intel() -> dict:
    """Return an empty intel dict for IPs that could not be enriched"""
    return {
        "country":    None,
        "org":        None,
        "asn":        None,
        "city":       None,
        "is_tor":     False,
        "is_private": False,
    }


def _is_private(ip: str) -> bool:
    """Return True if IP is RFC 1918, loopback or link-local"""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False
