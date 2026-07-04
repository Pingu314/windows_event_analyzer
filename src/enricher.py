"""
enricher.py - Enrichment Pipeline for Windows Event Analyzer

Enriches alerts with threat intelligence, user context, computer context,
process context, privilege context and IP reputation data.

Classes:
    IPEnricher              - ipinfo.io geolocation, ASN, Tor detection
    AbuseIPDBEnricher       - AbuseIPDB reputation scoring
    VirusTotalEnricher      - VirusTotal vendor verdicts for IPs
    GreyNoiseEnricher       - GreyNoise scanner/noise classification
    UserContextEnricher     - service accounts, machine accounts, watchlist
    ComputerContextEnricher - DC/server/workstation classification, HVA
    ProcessContextEnricher  - LOLBin detection, path anomalies
    PrivilegeEnricher       - sensitive privilege detection from 4672/4703
    AlertContextEnricher    - orchestrator; runs all enrichers in sequence

Usage:
    # Full pipeline
    enricher = AlertContextEnricher()
    alerts = enricher.enrich_alerts(alerts)

    # Single enricher
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

from config.settings import (
    ABUSEIPDB_BASE_URL,
    ABUSEIPDB_REQUEST_TIMEOUT,
    DC_NAMING_PREFIXES,
    GREYNOISE_BASE_URL,
    GREYNOISE_REQUEST_TIMEOUT,
    HIGH_RISK_COUNTRIES,
    HIGH_RISK_USERNAMES,
    HIGH_VALUE_ASSETS,
    IPINFO_BASE_URL,
    IPINFO_REQUEST_TIMEOUT,
    LOLBINS,
    MACHINE_ACCOUNT_SUFFIX,
    SENSITIVE_PRIVILEGES,
    SERVER_NAMING_PREFIXES,
    SERVICE_ACCOUNT_PATTERNS,
    SYSTEM_PROCESS_PATHS,
    VIRUSTOTAL_BASE_URL,
    VIRUSTOTAL_REQUEST_TIMEOUT,
    WORKSTATION_NAMING_PREFIXES,
)

logger = logging.getLogger(__name__)

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

_IPINFO_TOKEN = os.environ.get("IPINFO_TOKEN", "")
_ABUSEIPDB_TOKEN = os.environ.get("ABUSEIPDB_TOKEN", "")
_VIRUSTOTAL_TOKEN = os.environ.get("VIRUSTOTAL_TOKEN", "")
_GREYNOISE_TOKEN = os.environ.get("GREYNOISE_TOKEN", "")
_GREYNOISE_COMMUNITY = (
    os.environ.get("GREYNOISE_COMMUNITY", "").lower() in ("1", "true", "yes")
)


# ---------------------------------------------------------------------------
# IPEnricher
# ---------------------------------------------------------------------------

class IPEnricher:
    """Enriches alert IPs with ipinfo.io geolocation, ASN and Tor data.

    Features:
      - In-memory cache - each IP queried at most once per run
      - RFC 1918 / loopback / link-local skip
      - Graceful degradation without token
      - Tor exit node detection via org field
      - High-risk country flagging via settings.HIGH_RISK_COUNTRIES
    """

    def __init__(self, token: str = "") -> None:
        self._token = token or _IPINFO_TOKEN
        self._cache: dict[str, dict | None] = {}
        if not self._token:
            logger.info(
                "No IPINFO_TOKEN set - IP enrichment disabled. "
                "Set IPINFO_TOKEN in .env to enable."
            )

    def enrich_alerts(self, alerts: list[dict]) -> list[dict]:
        """Add 'intel' key to each alert with IP geolocation data.

        Args:
            alerts: Alert list from detector.run_all_detections().

        Returns:
            Same list with 'intel' key added to each alert.
        """
        for alert in alerts:
            ip = alert.get("ip")
            alert["intel"] = self.get_ip_info(ip) if ip else _no_intel()
        return alerts

    def get_ip_info(self, ip: str) -> dict:
        """Look up a single IP address.

        Args:
            ip: IPv4 or IPv6 address string.

        Returns:
            Intel dict with country, org, asn, city, is_tor,
            is_private, is_high_risk_country.
        """
        if not ip:
            return _no_intel()

        if _is_private(ip):
            return {
                "country":              "PRIVATE",
                "org":                  "Internal Network",
                "asn":                  None,
                "city":                 None,
                "is_tor":               False,
                "is_private":           True,
                "is_high_risk_country": False,
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
        # Token goes in the Authorization header, not the URL, so it cannot
        # leak into proxy or server access logs.
        url = f"{IPINFO_BASE_URL}/{ip}/json"
        try:
            req = urllib.request.Request(
                url,
                headers={"Accept": "application/json",
                         "Authorization": f"Bearer {self._token}",
                         "User-Agent": "windows-event-analyzer/1.0"},
            )
            with urllib.request.urlopen(req, timeout=IPINFO_REQUEST_TIMEOUT) as resp:
                data = json.loads(resp.read().decode())

            org = data.get("org", "")
            asn = org.split()[0] if org and org.startswith("AS") else None
            is_tor = "tor" in org.lower() if org else False
            country = data.get("country")

            return {
                "country":              country,
                "org":                  org or None,
                "asn":                  asn,
                "city":                 data.get("city"),
                "is_tor":               is_tor,
                "is_private":           False,
                "is_high_risk_country": country in HIGH_RISK_COUNTRIES,
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
# AbuseIPDBEnricher
# ---------------------------------------------------------------------------

class AbuseIPDBEnricher:
    """Enriches alert IPs with AbuseIPDB reputation scores.

    Requires ABUSEIPDB_TOKEN in .env or environment.
    Free tier: 1000 checks/day.
    Adds 'abuse_intel' key to each alert.
    """

    def __init__(self, token: str = "") -> None:
        self._token = token or _ABUSEIPDB_TOKEN
        self._cache: dict[str, dict | None] = {}
        if not self._token:
            logger.info(
                "No ABUSEIPDB_TOKEN set - AbuseIPDB enrichment disabled. "
                "Set ABUSEIPDB_TOKEN in .env to enable."
            )

    def enrich_alerts(self, alerts: list[dict]) -> list[dict]:
        """Add 'abuse_intel' key to each alert.

        Args:
            alerts: Alert list.

        Returns:
            Same list with 'abuse_intel' key added.
        """
        for alert in alerts:
            ip = alert.get("ip")
            alert["abuse_intel"] = (
                self.get_abuse_score(ip) if ip else _no_abuse_intel()
            )
        return alerts

    def get_abuse_score(self, ip: str) -> dict:
        """Query AbuseIPDB for a single IP.

        Args:
            ip: IPv4 or IPv6 address string.

        Returns:
            Dict with abuse_score (0-100), total_reports, last_reported,
            is_whitelisted, usage_type, isp.
        """
        if not ip or _is_private(ip):
            return _no_abuse_intel()

        if ip in self._cache:
            return self._cache[ip] or _no_abuse_intel()

        if not self._token:
            self._cache[ip] = None
            return _no_abuse_intel()

        result = self._query(ip)
        self._cache[ip] = result
        return result or _no_abuse_intel()

    def _query(self, ip: str) -> dict | None:
        url = f"{ABUSEIPDB_BASE_URL}/check"
        try:
            params = f"ipAddress={ip}&maxAgeInDays=90"
            req = urllib.request.Request(
                f"{url}?{params}",
                headers={
                    "Key": self._token,
                    "Accept": "application/json",
                    "User-Agent": "windows-event-analyzer/1.0",
                },
            )
            with urllib.request.urlopen(
                req, timeout=ABUSEIPDB_REQUEST_TIMEOUT
            ) as resp:
                data = json.loads(resp.read().decode()).get("data", {})

            return {
                "abuse_score":    data.get("abuseConfidenceScore", 0),
                "total_reports":  data.get("totalReports", 0),
                "last_reported":  data.get("lastReportedAt"),
                "is_whitelisted": data.get("isWhitelisted", False),
                "usage_type":     data.get("usageType"),
                "isp":            data.get("isp"),
            }
        except urllib.error.HTTPError as e:
            if e.code == 429:
                logger.warning("AbuseIPDB rate limit hit for %s", ip)
            else:
                logger.debug("AbuseIPDB HTTP error for %s: %s", ip, e)
            return None
        except urllib.error.URLError as e:
            logger.debug("AbuseIPDB connection error for %s: %s", ip, e)
            return None
        except Exception as e:
            logger.debug("AbuseIPDB unexpected error for %s: %s", ip, e)
            return None


# ---------------------------------------------------------------------------
# VirusTotalEnricher
# ---------------------------------------------------------------------------

class VirusTotalEnricher:
    """Enriches alert IPs with VirusTotal vendor verdicts.

    Requires VIRUSTOTAL_TOKEN in .env or environment.
    Free tier: 500 lookups/day, 4/minute.
    Adds 'vt_intel' key to each alert.
    """

    def __init__(self, token: str = "") -> None:
        self._token = token or _VIRUSTOTAL_TOKEN
        self._cache: dict[str, dict | None] = {}
        if not self._token:
            logger.info(
                "No VIRUSTOTAL_TOKEN set - VirusTotal enrichment disabled. "
                "Set VIRUSTOTAL_TOKEN in .env to enable."
            )

    def enrich_alerts(self, alerts: list[dict]) -> list[dict]:
        """Add 'vt_intel' key to each alert."""
        for alert in alerts:
            ip = alert.get("ip")
            alert["vt_intel"] = self.get_verdict(ip) if ip else _no_vt_intel()
        return alerts

    def get_verdict(self, ip: str) -> dict:
        """Query VirusTotal for a single IP.

        Returns:
            Dict with malicious (vendor count), suspicious, harmless,
            reputation, as_owner, country.
        """
        if not ip or _is_private(ip):
            return _no_vt_intel()
        if ip in self._cache:
            return self._cache[ip] or _no_vt_intel()
        if not self._token:
            self._cache[ip] = None
            return _no_vt_intel()

        result = self._query(ip)
        self._cache[ip] = result
        return result or _no_vt_intel()

    def _query(self, ip: str) -> dict | None:
        url = f"{VIRUSTOTAL_BASE_URL}/ip_addresses/{ip}"
        try:
            req = urllib.request.Request(
                url,
                headers={"x-apikey": self._token,
                         "Accept": "application/json",
                         "User-Agent": "windows-event-analyzer/1.0"},
            )
            with urllib.request.urlopen(
                req, timeout=VIRUSTOTAL_REQUEST_TIMEOUT
            ) as resp:
                attrs = (json.loads(resp.read().decode())
                         .get("data", {}).get("attributes", {}))

            stats = attrs.get("last_analysis_stats", {})
            return {
                "malicious":  stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless":   stats.get("harmless", 0),
                "reputation": attrs.get("reputation"),
                "as_owner":   attrs.get("as_owner"),
                "country":    attrs.get("country"),
            }
        except urllib.error.HTTPError as e:
            if e.code == 429:
                logger.warning("VirusTotal rate limit hit for %s", ip)
            else:
                logger.debug("VirusTotal HTTP error for %s: %s", ip, e)
            return None
        except urllib.error.URLError as e:
            logger.debug("VirusTotal connection error for %s: %s", ip, e)
            return None
        except Exception as e:
            logger.debug("VirusTotal unexpected error for %s: %s", ip, e)
            return None


# ---------------------------------------------------------------------------
# GreyNoiseEnricher
# ---------------------------------------------------------------------------

class GreyNoiseEnricher:
    """Enriches alert IPs with GreyNoise Community classification.

    Tells scanners/background noise apart from targeted attackers:
      - noise=True  → IP mass-scans the whole internet (opportunistic)
      - riot=True   → IP belongs to a common business service (benign)
      - classification: 'benign' | 'malicious' | 'unknown'

    Auth modes (docs.greynoise.io/docs/using-the-greynoise-community-api):
      - GREYNOISE_TOKEN set        → authenticated, 50 lookups/week (free acct)
      - GREYNOISE_COMMUNITY=true   → unauthenticated, 10 IP lookups/day
      - neither                    → enrichment disabled (no IPs are sent
                                     to a third party without opt-in)

    Adds 'greynoise_intel' key to each alert.
    """

    def __init__(self, token: str = "",
                 allow_unauthenticated: bool | None = None) -> None:
        self._token = token or _GREYNOISE_TOKEN
        if allow_unauthenticated is None:
            allow_unauthenticated = _GREYNOISE_COMMUNITY
        self._enabled = bool(self._token) or allow_unauthenticated
        self._cache: dict[str, dict | None] = {}
        if not self._enabled:
            logger.info(
                "GreyNoise enrichment disabled. Set GREYNOISE_TOKEN in .env "
                "(authenticated, 50/week) or GREYNOISE_COMMUNITY=true "
                "(unauthenticated, 10 IPs/day) to enable."
            )

    def enrich_alerts(self, alerts: list[dict]) -> list[dict]:
        """Add 'greynoise_intel' key to each alert."""
        for alert in alerts:
            ip = alert.get("ip")
            alert["greynoise_intel"] = (
                self.get_classification(ip) if ip else _no_greynoise_intel()
            )
        return alerts

    def get_classification(self, ip: str) -> dict:
        """Query GreyNoise Community API for a single IP.

        Returns:
            Dict with classification, is_noise, is_riot, actor_name, last_seen.
        """
        if not ip or _is_private(ip):
            return _no_greynoise_intel()
        if ip in self._cache:
            return self._cache[ip] or _no_greynoise_intel()
        if not self._enabled:
            self._cache[ip] = None
            return _no_greynoise_intel()

        result = self._query(ip)
        self._cache[ip] = result
        return result or _no_greynoise_intel()

    def _query(self, ip: str) -> dict | None:
        url = f"{GREYNOISE_BASE_URL}/{ip}"
        headers = {"Accept": "application/json",
                   "User-Agent": "windows-event-analyzer/1.0"}
        if self._token:
            # unauthenticated community access works without this header,
            # just with a lower rate limit
            headers["key"] = self._token
        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(
                req, timeout=GREYNOISE_REQUEST_TIMEOUT
            ) as resp:
                data = json.loads(resp.read().decode())

            return {
                "classification": data.get("classification", "unknown"),
                "is_noise":       data.get("noise", False),
                "is_riot":        data.get("riot", False),
                "actor_name":     data.get("name"),
                "last_seen":      data.get("last_seen"),
            }
        except urllib.error.HTTPError as e:
            if e.code == 404:
                # GreyNoise has never observed this IP - that is a result too
                return {
                    "classification": "unknown",
                    "is_noise":       False,
                    "is_riot":        False,
                    "actor_name":     None,
                    "last_seen":      None,
                }
            if e.code == 429:
                logger.warning("GreyNoise rate limit hit for %s", ip)
            else:
                logger.debug("GreyNoise HTTP error for %s: %s", ip, e)
            return None
        except urllib.error.URLError as e:
            logger.debug("GreyNoise connection error for %s: %s", ip, e)
            return None
        except Exception as e:
            logger.debug("GreyNoise unexpected error for %s: %s", ip, e)
            return None


# ---------------------------------------------------------------------------
# UserContextEnricher
# ---------------------------------------------------------------------------

class UserContextEnricher:
    """Classifies usernames in alerts - no API required.

    Detects service accounts, machine accounts, high-risk usernames
    and custom watchlist matches using settings.py patterns.

    Adds 'user_context' key to each alert.
    """

    def __init__(self, watchlist: list[str] | None = None) -> None:
        self._watchlist = {u.lower() for u in (watchlist or [])}

    def enrich_alerts(self, alerts: list[dict]) -> list[dict]:
        """Add 'user_context' key to each alert.

        Args:
            alerts: Alert list.

        Returns:
            Same list with 'user_context' key added.
        """
        for alert in alerts:
            user = alert.get("user")
            alert["user_context"] = (
                self.classify(user) if user else _no_user_context()
            )
        return alerts

    def classify(self, username: str) -> dict:
        """Classify a username.

        Args:
            username: Normalised (lowercase) username string.

        Returns:
            Dict with is_service_account, is_machine_account,
            is_high_risk, is_watchlisted, account_type.
        """
        u = username.lower().strip()

        is_machine = u.endswith(MACHINE_ACCOUNT_SUFFIX)
        # Prefix patterns match at the start; suffix matching only with the
        # separator included ('backup_svc' matches '_svc', 'lisa' does not
        # match 'sa-').
        is_service = any(
            u.startswith(p) or (p.startswith(("_", "-")) and u.endswith(p))
            for p in SERVICE_ACCOUNT_PATTERNS
        )
        is_high_risk = u in HIGH_RISK_USERNAMES
        is_watchlisted = u in self._watchlist

        if is_machine:
            account_type = "machine"
        elif is_service:
            account_type = "service"
        elif is_high_risk:
            account_type = "privileged"
        else:
            account_type = "standard"

        return {
            "is_service_account": is_service,
            "is_machine_account": is_machine,
            "is_high_risk":       is_high_risk,
            "is_watchlisted":     is_watchlisted,
            "account_type":       account_type,
        }


# ---------------------------------------------------------------------------
# ComputerContextEnricher
# ---------------------------------------------------------------------------

class ComputerContextEnricher:
    """Classifies computers in alerts by naming convention - no API required.

    Uses settings.DC_NAMING_PREFIXES, SERVER_NAMING_PREFIXES,
    WORKSTATION_NAMING_PREFIXES and HIGH_VALUE_ASSETS.

    Adds 'computer_context' key to each alert.
    """

    def enrich_alerts(self, alerts: list[dict]) -> list[dict]:
        """Add 'computer_context' key to each alert.

        Args:
            alerts: Alert list.

        Returns:
            Same list with 'computer_context' key added.
        """
        for alert in alerts:
            computer = alert.get("computer")
            alert["computer_context"] = (
                self.classify(computer) if computer else _no_computer_context()
            )
        return alerts

    def classify(self, computer: str) -> dict:
        """Classify a computer name.

        Args:
            computer: Normalised (lowercase) computer name or FQDN.

        Returns:
            Dict with computer_type, is_domain_controller,
            is_server, is_workstation, is_high_value.
        """
        c = computer.lower().split(".")[0]  # strip domain suffix

        is_dc = any(c.startswith(p) for p in DC_NAMING_PREFIXES)
        is_server = any(c.startswith(p) for p in SERVER_NAMING_PREFIXES)
        is_workstation = any(c.startswith(p) for p in WORKSTATION_NAMING_PREFIXES)
        is_hva = (
            any(hva.lower() in c for hva in HIGH_VALUE_ASSETS)
            if HIGH_VALUE_ASSETS else False
        )

        if is_dc:
            computer_type = "domain_controller"
        elif is_server:
            computer_type = "server"
        elif is_workstation:
            computer_type = "workstation"
        else:
            computer_type = "unknown"

        return {
            "computer_type":        computer_type,
            "is_domain_controller": is_dc,
            "is_server":            is_server,
            "is_workstation":       is_workstation,
            "is_high_value":        is_hva,
        }


# ---------------------------------------------------------------------------
# ProcessContextEnricher
# ---------------------------------------------------------------------------

class ProcessContextEnricher:
    """Enriches process-related alerts with LOLBin and path anomaly detection.

    Reads process_name and full path from triggering events.
    Checks against settings.LOLBINS and settings.SYSTEM_PROCESS_PATHS.

    Adds 'process_context' key to Execution and Persistence alerts.
    """

    def enrich_alerts(self, alerts: list[dict]) -> list[dict]:
        """Add 'process_context' key to execution/persistence alerts.

        Args:
            alerts: Alert list.

        Returns:
            Same list with 'process_context' key added.
        """
        for alert in alerts:
            category = alert.get("category", "")
            if category in ("Execution", "Persistence"):
                process_name = None
                full_path = None
                for event in alert.get("events", []):
                    raw = event.get("raw", {})
                    full_path = raw.get("NewProcessName", "").lower()
                    process_name = event.get("process_name")
                    if process_name:
                        break
                alert["process_context"] = self.classify(process_name, full_path)
            else:
                alert["process_context"] = None
        return alerts

    def classify(self, process_name: str | None,
                 full_path: str | None = None) -> dict:
        """Classify a process by name and path.

        Args:
            process_name: Basename of the process (e.g. 'cmd.exe').
            full_path: Full path if available.

        Returns:
            Dict with is_lolbin, is_system_path, path_anomaly, process_name.
        """
        if not process_name:
            return {
                "is_lolbin":      False,
                "is_system_path": None,
                "path_anomaly":   False,
                "process_name":   None,
            }

        name = process_name.lower()
        path = (full_path or "").lower()

        is_lolbin = name in LOLBINS
        is_system = (
            any(path.startswith(sp) for sp in SYSTEM_PROCESS_PATHS)
            if path else None
        )
        # Path anomaly: LOLBin running outside system directories
        path_anomaly = bool(is_lolbin and path and not is_system)

        return {
            "is_lolbin":      is_lolbin,
            "is_system_path": is_system,
            "path_anomaly":   path_anomaly,
            "process_name":   name,
        }


# ---------------------------------------------------------------------------
# PrivilegeEnricher
# ---------------------------------------------------------------------------

class PrivilegeEnricher:
    """Parses privilege names from 4672/4703 events, flags sensitive ones.

    Reads PrivilegeList from event raw data and checks against
    settings.SENSITIVE_PRIVILEGES.

    Adds 'privilege_context' key to privilege-related alerts.
    """

    def enrich_alerts(self, alerts: list[dict]) -> list[dict]:
        """Add 'privilege_context' key to privilege-related alerts.

        Args:
            alerts: Alert list.

        Returns:
            Same list with 'privilege_context' key added.
        """
        for alert in alerts:
            event_ids = {e.get("event_id") for e in alert.get("events", [])}
            if event_ids & {4672, 4703, 4704, 4705}:
                privs = self._extract_privileges(alert)
                alert["privilege_context"] = self.classify(privs)
            else:
                alert["privilege_context"] = None
        return alerts

    def classify(self, privileges: list[str]) -> dict:
        """Classify a list of privilege names.

        Args:
            privileges: List of Windows privilege name strings.

        Returns:
            Dict with privileges, sensitive_privileges, has_sensitive,
            highest_risk_privilege.
        """
        sensitive = [p for p in privileges if p in SENSITIVE_PRIVILEGES]
        return {
            "privileges":             privileges,
            "sensitive_privileges":   sensitive,
            "has_sensitive":          bool(sensitive),
            "highest_risk_privilege": sensitive[0] if sensitive else None,
        }

    def _extract_privileges(self, alert: dict) -> list[str]:
        privs: list[str] = []
        for event in alert.get("events", []):
            raw = event.get("raw", {})
            priv_list = raw.get("PrivilegeList", "")
            if priv_list:
                privs.extend(
                    p.strip()
                    for p in priv_list.replace("\t", "\n").splitlines()
                    if p.strip().startswith("Se")
                )
        return list(dict.fromkeys(privs))


# ---------------------------------------------------------------------------
# AlertContextEnricher (orchestrator)
# ---------------------------------------------------------------------------

class AlertContextEnricher:
    """Orchestrator that runs all enrichers in sequence.

    Pipeline:
        IPEnricher → AbuseIPDBEnricher → VirusTotalEnricher →
        GreyNoiseEnricher → UserContextEnricher → ComputerContextEnricher →
        ProcessContextEnricher → PrivilegeEnricher

    API enrichers (IP, AbuseIPDB, VirusTotal, GreyNoise) degrade gracefully
    without tokens. All other enrichers run unconditionally - no API required.

    Usage:
        enricher = AlertContextEnricher()
        alerts = enricher.enrich_alerts(alerts)
    """

    def __init__(
        self,
        ip_token: str = "",
        abuse_token: str = "",
        vt_token: str = "",
        greynoise_token: str = "",
        user_watchlist: list[str] | None = None,
    ) -> None:
        self._ip = IPEnricher(token=ip_token)
        self._abuse = AbuseIPDBEnricher(token=abuse_token)
        self._vt = VirusTotalEnricher(token=vt_token)
        self._greynoise = GreyNoiseEnricher(token=greynoise_token)
        self._user = UserContextEnricher(watchlist=user_watchlist)
        self._computer = ComputerContextEnricher()
        self._process = ProcessContextEnricher()
        self._privilege = PrivilegeEnricher()

    def enrich_alerts(self, alerts: list[dict]) -> list[dict]:
        """Run all enrichers against the alert list.

        Args:
            alerts: Alert list from detector.run_all_detections().

        Returns:
            Same list with all enrichment keys added.
        """
        alerts = self._ip.enrich_alerts(alerts)
        alerts = self._abuse.enrich_alerts(alerts)
        alerts = self._vt.enrich_alerts(alerts)
        alerts = self._greynoise.enrich_alerts(alerts)
        alerts = self._user.enrich_alerts(alerts)
        alerts = self._computer.enrich_alerts(alerts)
        alerts = self._process.enrich_alerts(alerts)
        alerts = self._privilege.enrich_alerts(alerts)
        return alerts


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _no_intel() -> dict:
    return {
        "country":              None,
        "org":                  None,
        "asn":                  None,
        "city":                 None,
        "is_tor":               False,
        "is_private":           False,
        "is_high_risk_country": False,
    }


def _no_abuse_intel() -> dict:
    return {
        "abuse_score":    None,
        "total_reports":  None,
        "last_reported":  None,
        "is_whitelisted": None,
        "usage_type":     None,
        "isp":            None,
    }


def _no_vt_intel() -> dict:
    return {
        "malicious":  None,
        "suspicious": None,
        "harmless":   None,
        "reputation": None,
        "as_owner":   None,
        "country":    None,
    }


def _no_greynoise_intel() -> dict:
    return {
        "classification": None,
        "is_noise":       False,
        "is_riot":        False,
        "actor_name":     None,
        "last_seen":      None,
    }


def _no_user_context() -> dict:
    return {
        "is_service_account": False,
        "is_machine_account": False,
        "is_high_risk":       False,
        "is_watchlisted":     False,
        "account_type":       "unknown",
    }


def _no_computer_context() -> dict:
    return {
        "computer_type":        "unknown",
        "is_domain_controller": False,
        "is_server":            False,
        "is_workstation":       False,
        "is_high_value":        False,
    }


def _is_private(ip: str) -> bool:
    """Return True if IP is RFC 1918, loopback or link-local."""
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False
