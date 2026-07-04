"""Tests for src.correlator - incident grouping."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from src.correlator import correlate, serialise_incident
from src.detector import run_all_detections
from src.mitre_mapper import map_many
from src.risk_scorer import score_all
from tests.conftest import make_event

BASE = datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc)


def _analyzed(events):
    return map_many(score_all(run_all_detections(events)))


def test_alerts_sharing_ip_form_one_incident():
    events = [
        make_event(4625, timestamp=BASE + timedelta(seconds=i * 10),
                   user="admin", ip_address="9.9.9.9")
        for i in range(5)
    ] + [
        make_event(4740, timestamp=BASE + timedelta(minutes=2),
                   user="admin", ip_address="9.9.9.9"),
    ]
    alerts = _analyzed(events)
    incidents = correlate(alerts)
    assert len(incidents) == 1
    incident = incidents[0]
    assert incident["incident_id"] == "INC-001"
    assert incident["alert_count"] == len(alerts)
    assert "9.9.9.9" in incident["ips"]
    assert all(a["incident_id"] == "INC-001" for a in alerts)


def test_time_window_splits_incidents():
    def wave(offset, user):
        return [
            make_event(4625, timestamp=BASE + offset + timedelta(seconds=i * 10),
                       user=user, ip_address="9.9.9.9")
            for i in range(5)
        ] + [
            make_event(4740, timestamp=BASE + offset + timedelta(minutes=2),
                       user=user),
        ]

    alerts = _analyzed(wave(timedelta(0), "alice")
                       + wave(timedelta(hours=6), "bob"))
    incidents = correlate(alerts, window_minutes=30)
    # both waves come from the same IP, but 6h apart -> two incidents
    assert len(incidents) == 2


def test_singleton_alert_is_not_an_incident():
    alerts = _analyzed([make_event(1102, user="jsmith")])
    incidents = correlate(alerts)
    assert incidents == []
    assert alerts[0]["incident_id"] is None


def test_shared_user_bridges_ip_and_local_alerts():
    events = [
        # network stage carries ip + user
        make_event(4625, timestamp=BASE + timedelta(seconds=i * 10),
                   user="svc_backup", ip_address="9.9.9.9")
        for i in range(5)
    ] + [
        # local stage carries only the user
        make_event(4698, timestamp=BASE + timedelta(minutes=5),
                   user="svc_backup", task_name="\\Evil"),
    ]
    alerts = _analyzed(events)
    incidents = correlate(alerts)
    assert len(incidents) == 1
    assert "persist-001" in incidents[0]["rule_ids"]


def test_incident_severity_and_score_aggregation():
    events = [
        make_event(4625, timestamp=BASE + timedelta(seconds=i * 10),
                   user="admin", ip_address="9.9.9.9")
        for i in range(5)
    ] + [
        make_event(1102, timestamp=BASE + timedelta(minutes=3), user="admin"),
    ]
    alerts = _analyzed(events)
    incidents = correlate(alerts)
    assert incidents[0]["severity"] == "CRITICAL"     # from 1102
    assert incidents[0]["score"] == 100
    assert len(incidents[0]["categories"]) >= 2


def test_serialise_incident_is_json_safe():
    import json

    events = [
        make_event(4625, timestamp=BASE + timedelta(seconds=i * 10),
                   user="admin", ip_address="9.9.9.9")
        for i in range(5)
    ] + [
        make_event(4740, timestamp=BASE + timedelta(minutes=1), user="admin"),
    ]
    incidents = correlate(_analyzed(events))
    data = serialise_incident(incidents[0])
    json.dumps(data)                                  # must not raise
    assert "alerts" not in data
    assert data["top_alerts"]
    assert data["start"] and data["end"]


def test_correlate_empty():
    assert correlate([]) == []
