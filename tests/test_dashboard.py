"""Tests for src.dashboard - Flask REST API endpoints."""
from __future__ import annotations

import io

import pytest

import src.dashboard as dashboard


@pytest.fixture
def client():
    dashboard.app.config["TESTING"] = True
    # start each test with a cold cache
    dashboard._cached_alerts = None
    dashboard._cache_source = ""
    dashboard._cache_generated_at = ""
    with dashboard.app.test_client() as c:
        yield c


def _csv_upload(name="upload.csv") -> tuple[io.BytesIO, str]:
    content = (
        "Event ID,Date and Time,Computer,User,Logon Type,Source Network Address\n"
        "4625,01/15/2026 09:00:00,ws01,admin,3,185.220.101.1\n"
        "4625,01/15/2026 09:00:10,ws01,admin,3,185.220.101.1\n"
        "4625,01/15/2026 09:00:20,ws01,admin,3,185.220.101.1\n"
        "4625,01/15/2026 09:00:30,ws01,admin,3,185.220.101.1\n"
        "4625,01/15/2026 09:00:40,ws01,admin,3,185.220.101.1\n"
        "1102,01/15/2026 09:05:00,ws01,admin,,\n"
    )
    return io.BytesIO(content.encode()), name


def test_home(client):
    resp = client.get("/")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["tool"] == "windows-event-analyzer"
    assert "endpoints" in body


def test_health(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


def test_alerts_and_pagination(client):
    resp = client.get("/alerts")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["total_alerts"] == len(body["alerts"])
    for alert in body["alerts"]:
        assert "events" not in alert
        assert "triggering_event_ids" in alert

    page = client.get("/alerts?limit=2&offset=1").get_json()
    assert page["returned"] <= 2
    assert page["offset"] == 1


def test_alerts_summary(client):
    body = client.get("/alerts/summary").get_json()
    assert set(body["by_severity"]) == {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    assert body["total_alerts"] == sum(body["by_severity"].values())
    assert "top_rules" in body


def test_alerts_by_severity(client):
    body = client.get("/alerts/severity/critical").get_json()
    assert body["severity"] == "CRITICAL"
    for alert in body["alerts"]:
        assert alert["risk"]["severity"] == "CRITICAL"


def test_alerts_by_severity_invalid(client):
    resp = client.get("/alerts/severity/bogus")
    assert resp.status_code == 400
    assert "Invalid severity" in resp.get_json()["error"]


def test_alerts_by_rule(client):
    body = client.get("/alerts/evasion-001").get_json()
    assert body["rule_id"] == "evasion-001"
    for alert in body["alerts"]:
        assert alert["rule_id"] == "evasion-001"


def test_analyze_no_file(client):
    resp = client.post("/analyze", data={})
    assert resp.status_code == 400


def test_analyze_unsupported_extension(client):
    resp = client.post(
        "/analyze",
        data={"file": (io.BytesIO(b"x"), "notes.txt")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 400
    assert "Unsupported file type" in resp.get_json()["error"]


def test_analyze_csv_upload(client):
    resp = client.post(
        "/analyze",
        data={"file": _csv_upload()},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["files_processed"] == ["upload.csv"]
    assert body["total_alerts"] >= 2            # brute force + log cleared
    rule_ids = {a["rule_id"] for a in body["alerts"]}
    assert "brute-001" in rule_ids
    assert "evasion-001" in rule_ids
    assert body["summary"]["CRITICAL"] >= 1


def test_analyze_multiple_files(client):
    resp = client.post(
        "/analyze",
        data={"file": [_csv_upload("a.csv"), _csv_upload("b.csv")]},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    assert resp.get_json()["files_processed"] == ["a.csv", "b.csv"]


def test_analyze_threshold_override(client):
    resp = client.post(
        "/analyze?brute_threshold=99",
        data={"file": _csv_upload()},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 200
    rule_ids = {a["rule_id"] for a in resp.get_json()["alerts"]}
    assert "brute-001" not in rule_ids           # threshold too high to fire


def test_clear_cache(client):
    client.get("/alerts")                        # warm the cache
    resp = client.delete("/cache")
    assert resp.status_code == 200
    assert dashboard._cached_alerts is None


# ---------------------------------------------------------------------------
# Edge cases
# ---------------------------------------------------------------------------


def test_int_param_invalid_value_ignored(client):
    resp = client.get("/alerts?limit=abc&offset=xyz")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["offset"] == 0                   # invalid -> default


def test_alerts_with_missing_sample_log(client, monkeypatch, tmp_path):
    monkeypatch.setattr(dashboard, "_SAMPLE_LOG", tmp_path / "gone.csv")
    body = client.get("/alerts").get_json()
    assert body["total_alerts"] == 0


def test_summary_counts_tor_and_high_risk(client):
    dashboard._cached_alerts = [
        {"rule_id": "brute-001", "category": "Authentication",
         "risk": {"severity": "HIGH"},
         "intel": {"is_tor": True, "is_high_risk_country": False}},
        {"rule_id": "brute-002", "category": "Authentication",
         "risk": {"severity": "HIGH"},
         "intel": {"is_tor": False, "is_high_risk_country": True}},
    ]
    body = client.get("/alerts/summary").get_json()
    assert body["tor_source_alerts"] == 1
    assert body["high_risk_country_alerts"] == 1


def test_analyze_corrupt_file_returns_500(client):
    resp = client.post(
        "/analyze",
        data={"file": (io.BytesIO(b"this is not an evtx file"), "corrupt.evtx")},
        content_type="multipart/form-data",
    )
    assert resp.status_code == 500
    assert "error" in resp.get_json()


def test_incidents_endpoint(client):
    resp = client.get("/incidents")
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["total_incidents"] == len(body["incidents"])
    for incident in body["incidents"]:
        assert incident["incident_id"].startswith("INC-")
        assert "alerts" not in incident        # payloads stripped
        assert incident["alert_count"] >= 2
