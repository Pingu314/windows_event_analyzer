"""Tests for src.enricher - context classification and mocked API clients."""
from __future__ import annotations

import json
import urllib.error
import urllib.request

import pytest

from src.enricher import (
    AbuseIPDBEnricher,
    AlertContextEnricher,
    ComputerContextEnricher,
    GreyNoiseEnricher,
    IPEnricher,
    PrivilegeEnricher,
    ProcessContextEnricher,
    UserContextEnricher,
    VirusTotalEnricher,
    _is_private,
)
from tests.conftest import make_event


class _FakeResponse:
    def __init__(self, payload: dict):
        self._body = json.dumps(payload).encode()

    def read(self) -> bytes:
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _sample_alert(**overrides) -> dict:
    alert = {
        "rule_id": "brute-001", "rule": "Brute Force Login",
        "category": "Authentication", "mitre": "T1110.001",
        "sigma_severity": "high", "event_ids": [4625],
        "computer": "ws01", "user": "jsmith", "ip": None,
        "count": 5, "detail": "test", "events": [],
    }
    alert.update(overrides)
    return alert


# ---------------------------------------------------------------------------
# _is_private
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("ip,expected", [
    ("10.0.0.1", True),
    ("192.168.1.1", True),
    ("127.0.0.1", True),
    ("169.254.0.5", True),
    ("8.8.8.8", False),
    ("not-an-ip", False),
])
def test_is_private(ip, expected):
    assert _is_private(ip) is expected


# ---------------------------------------------------------------------------
# IPEnricher
# ---------------------------------------------------------------------------


def test_ip_enricher_private_ip_short_circuits():
    intel = IPEnricher(token="x").get_ip_info("10.0.0.1")
    assert intel["is_private"] is True
    assert intel["country"] == "PRIVATE"


def test_ip_enricher_without_token_degrades():
    intel = IPEnricher().get_ip_info("8.8.8.8")
    assert intel["country"] is None
    assert intel["is_tor"] is False


def test_ip_enricher_query_and_cache(monkeypatch):
    calls = []

    def fake_urlopen(req, timeout=None):
        calls.append(req.full_url)
        return _FakeResponse({"country": "NL", "city": "Amsterdam",
                              "org": "AS1101 Tor Foundation relay"})

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    enricher = IPEnricher(token="test-token")

    intel = enricher.get_ip_info("185.220.101.1")
    assert intel["country"] == "NL"
    assert intel["asn"] == "AS1101"
    assert intel["is_tor"] is True
    assert intel["is_high_risk_country"] is False

    enricher.get_ip_info("185.220.101.1")
    assert len(calls) == 1                      # cached, no second request
    assert "token" not in calls[0]              # token not leaked in URL


def test_ip_enricher_network_error_returns_no_intel(monkeypatch):
    def fake_urlopen(req, timeout=None):
        raise urllib.error.URLError("unreachable")

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    intel = IPEnricher(token="x").get_ip_info("8.8.8.8")
    assert intel["country"] is None


def test_ip_enricher_enrich_alerts_adds_intel_key():
    alerts = IPEnricher().enrich_alerts([_sample_alert(ip="10.0.0.1"),
                                         _sample_alert(ip=None)])
    assert alerts[0]["intel"]["is_private"] is True
    assert alerts[1]["intel"]["country"] is None


# ---------------------------------------------------------------------------
# AbuseIPDBEnricher
# ---------------------------------------------------------------------------


def test_abuse_enricher_query(monkeypatch):
    def fake_urlopen(req, timeout=None):
        return _FakeResponse({"data": {"abuseConfidenceScore": 97,
                                       "totalReports": 42,
                                       "usageType": "Data Center"}})

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    result = AbuseIPDBEnricher(token="x").get_abuse_score("45.83.64.1")
    assert result["abuse_score"] == 97
    assert result["total_reports"] == 42


def test_abuse_enricher_private_and_tokenless():
    assert AbuseIPDBEnricher(token="x").get_abuse_score("10.0.0.1")["abuse_score"] is None
    assert AbuseIPDBEnricher().get_abuse_score("8.8.8.8")["abuse_score"] is None


# ---------------------------------------------------------------------------
# UserContextEnricher
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("user,expected_type", [
    ("ws01$", "machine"),
    ("svc_sql", "service"),
    ("backup_svc", "service"),
    ("administrator", "privileged"),
    ("krbtgt", "privileged"),
    ("jsmith", "standard"),
    ("lisa", "standard"),      # regression: no longer matches 'sa-'
    ("teresa", "standard"),
])
def test_user_classification(user, expected_type):
    assert UserContextEnricher().classify(user)["account_type"] == expected_type


def test_user_watchlist():
    ctx = UserContextEnricher(watchlist=["JSmith"]).classify("jsmith")
    assert ctx["is_watchlisted"] is True


def test_user_enrich_alerts_handles_missing_user():
    alerts = UserContextEnricher().enrich_alerts([_sample_alert(user=None)])
    assert alerts[0]["user_context"]["account_type"] == "unknown"


# ---------------------------------------------------------------------------
# ComputerContextEnricher
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("computer,expected_type", [
    ("dc01.corp.local", "domain_controller"),
    ("srv-file01", "server"),
    ("sql01", "server"),
    ("ws01.corp.local", "workstation"),
    ("laptop-42", "workstation"),
    ("zebra", "unknown"),
])
def test_computer_classification(computer, expected_type):
    ctx = ComputerContextEnricher().classify(computer)
    assert ctx["computer_type"] == expected_type


# ---------------------------------------------------------------------------
# ProcessContextEnricher
# ---------------------------------------------------------------------------


def test_lolbin_outside_system_path_is_anomaly():
    ctx = ProcessContextEnricher().classify(
        "certutil.exe", "c:\\users\\bob\\downloads\\certutil.exe")
    assert ctx["is_lolbin"] is True
    assert ctx["is_system_path"] is False
    assert ctx["path_anomaly"] is True


def test_lolbin_in_system_path_not_anomaly():
    ctx = ProcessContextEnricher().classify(
        "certutil.exe", "c:\\windows\\system32\\certutil.exe")
    assert ctx["path_anomaly"] is False


def test_process_enricher_only_touches_exec_persistence():
    exec_alert = _sample_alert(
        category="Execution",
        events=[make_event(4688, process_name="certutil.exe",
                           raw={"NewProcessName":
                                "C:\\Users\\bob\\certutil.exe"})])
    auth_alert = _sample_alert(category="Authentication")
    alerts = ProcessContextEnricher().enrich_alerts([exec_alert, auth_alert])
    assert alerts[0]["process_context"]["is_lolbin"] is True
    assert alerts[1]["process_context"] is None


# ---------------------------------------------------------------------------
# PrivilegeEnricher
# ---------------------------------------------------------------------------


def test_privilege_extraction_and_classification():
    alert = _sample_alert(events=[make_event(
        4672, raw={"PrivilegeList":
                   "SeDebugPrivilege\n\t\tSeBackupPrivilege\n\t\tSeShutdownPrivilege"})])
    alerts = PrivilegeEnricher().enrich_alerts([alert])
    ctx = alerts[0]["privilege_context"]
    assert ctx["has_sensitive"] is True
    assert "SeDebugPrivilege" in ctx["sensitive_privileges"]
    assert "SeShutdownPrivilege" not in ctx["sensitive_privileges"]


def test_privilege_enricher_skips_non_privilege_alerts():
    alerts = PrivilegeEnricher().enrich_alerts(
        [_sample_alert(events=[make_event(4625)])])
    assert alerts[0]["privilege_context"] is None


# ---------------------------------------------------------------------------
# AlertContextEnricher orchestrator
# ---------------------------------------------------------------------------


def test_orchestrator_adds_all_context_keys():
    alerts = AlertContextEnricher().enrich_alerts([_sample_alert(ip="10.0.0.1")])
    alert = alerts[0]
    for key in ("intel", "abuse_intel", "user_context",
                "computer_context", "process_context", "privilege_context"):
        assert key in alert


# ---------------------------------------------------------------------------
# HTTP error handling (all API enrichers share the pattern)
# ---------------------------------------------------------------------------


def _http_error(code: int):
    return urllib.error.HTTPError("http://x", code, "err", {}, None)


@pytest.mark.parametrize("exc", [
    _http_error(429),
    _http_error(500),
    urllib.error.URLError("down"),
    RuntimeError("unexpected"),
])
def test_ipinfo_error_paths(monkeypatch, exc):
    def fake_urlopen(req, timeout=None):
        raise exc

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    intel = IPEnricher(token="x").get_ip_info("8.8.8.8")
    assert intel["country"] is None


@pytest.mark.parametrize("exc", [
    _http_error(429),
    _http_error(500),
    urllib.error.URLError("down"),
    RuntimeError("unexpected"),
])
def test_abuseipdb_error_paths(monkeypatch, exc):
    def fake_urlopen(req, timeout=None):
        raise exc

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    result = AbuseIPDBEnricher(token="x").get_abuse_score("8.8.8.8")
    assert result["abuse_score"] is None


def test_ip_enricher_empty_ip():
    assert IPEnricher(token="x").get_ip_info("")["country"] is None


# ---------------------------------------------------------------------------
# VirusTotalEnricher
# ---------------------------------------------------------------------------


def test_virustotal_query(monkeypatch):
    def fake_urlopen(req, timeout=None):
        assert req.headers.get("X-apikey") == "vt-token"
        return _FakeResponse({"data": {"attributes": {
            "last_analysis_stats": {"malicious": 11, "suspicious": 2,
                                    "harmless": 60},
            "reputation": -40,
            "as_owner": "EvilHost Ltd",
            "country": "RU",
        }}})

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    verdict = VirusTotalEnricher(token="vt-token").get_verdict("91.240.118.29")
    assert verdict["malicious"] == 11
    assert verdict["as_owner"] == "EvilHost Ltd"
    assert verdict["country"] == "RU"


def test_virustotal_private_tokenless_and_errors(monkeypatch):
    assert VirusTotalEnricher(token="x").get_verdict("10.0.0.1")["malicious"] is None
    assert VirusTotalEnricher().get_verdict("8.8.8.8")["malicious"] is None

    def fake_urlopen(req, timeout=None):
        raise _http_error(429)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    assert VirusTotalEnricher(token="x").get_verdict("8.8.8.8")["malicious"] is None


def test_virustotal_enrich_alerts():
    alerts = VirusTotalEnricher().enrich_alerts([_sample_alert(ip=None)])
    assert alerts[0]["vt_intel"]["malicious"] is None


# ---------------------------------------------------------------------------
# GreyNoiseEnricher
# ---------------------------------------------------------------------------


def test_greynoise_query(monkeypatch):
    def fake_urlopen(req, timeout=None):
        return _FakeResponse({"classification": "malicious", "noise": True,
                              "riot": False, "name": "unknown scanner",
                              "last_seen": "2026-07-01"})

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    result = GreyNoiseEnricher(token="gn").get_classification("91.240.118.29")
    assert result["classification"] == "malicious"
    assert result["is_noise"] is True


def test_greynoise_404_means_unobserved(monkeypatch):
    def fake_urlopen(req, timeout=None):
        raise _http_error(404)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    # note: TEST-NET ranges (203.0.113.x) count as private in ipaddress,
    # so a real public IP is needed to reach the HTTP layer
    result = GreyNoiseEnricher(token="gn").get_classification("91.240.118.29")
    assert result["classification"] == "unknown"
    assert result["is_noise"] is False


@pytest.mark.parametrize("exc", [
    _http_error(429),
    _http_error(500),
    urllib.error.URLError("down"),
    RuntimeError("unexpected"),
])
def test_greynoise_error_paths(monkeypatch, exc):
    def fake_urlopen(req, timeout=None):
        raise exc

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    result = GreyNoiseEnricher(token="gn").get_classification("8.8.8.8")
    assert result["classification"] is None


def test_greynoise_private_and_tokenless():
    assert GreyNoiseEnricher(token="x").get_classification("10.0.0.1")["is_noise"] is False
    assert GreyNoiseEnricher().get_classification("8.8.8.8")["classification"] is None


def test_orchestrator_includes_new_intel_keys():
    alerts = AlertContextEnricher().enrich_alerts([_sample_alert(ip="10.0.0.1")])
    assert "vt_intel" in alerts[0]
    assert "greynoise_intel" in alerts[0]
