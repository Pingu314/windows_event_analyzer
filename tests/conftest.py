"""
conftest.py - Shared pytest fixtures for Windows Event Analyzer tests
"""
from __future__ import annotations

import csv
import json as _json
from datetime import datetime, timezone
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Event factory helpers
# ---------------------------------------------------------------------------

def make_event(
    event_id: int,
    timestamp: datetime | None = None,
    user: str | None = "jsmith",
    computer: str = "ws01.corp.local",
    ip_address: str | None = None,
    logon_type: int | None = None,
    process_name: str | None = None,
    task_name: str | None = None,
    service_name: str | None = None,
    message: str = "",
    raw: dict | None = None,
) -> dict:
    """Build a normalised event dict for testing."""
    return {
        "event_id":     event_id,
        "timestamp":    timestamp or datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc),
        "source":       "Microsoft-Windows-Security-Auditing",
        "computer":     computer,
        "user":         user,
        "level":        "Information",
        "message":      message,
        "logon_type":   logon_type,
        "ip_address":   ip_address,
        "process_name": process_name,
        "task_name":    task_name,
        "service_name": service_name,
        "raw":          raw or {},
    }


def make_events(
    event_id: int,
    count: int,
    base_time: datetime | None = None,
    interval_seconds: int = 1,
    **kwargs,
) -> list[dict]:
    """Build a list of similar events spaced by interval_seconds."""
    base = base_time or datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc)
    from datetime import timedelta
    return [
        make_event(
            event_id,
            timestamp=base + timedelta(seconds=i * interval_seconds),
            **kwargs,
        )
        for i in range(count)
    ]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def sample_event():
    """Single generic information event."""
    return make_event(4624, logon_type=3, ip_address="10.0.0.15")


@pytest.fixture
def brute_force_events():
    """5 failed logon events from same IP within 5 minutes - triggers brute-001."""
    return make_events(
        4625,
        count=5,
        ip_address="185.220.101.1",
        user="admin",
        interval_seconds=10,
    )


@pytest.fixture
def spray_events():
    """Failed logons targeting 4 distinct accounts from same IP - triggers brute-002."""
    from datetime import timedelta
    base = datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc)
    users = ["admin", "guest", "jsmith", "svc_backup"]
    return [
        make_event(
            4625,
            timestamp=base + timedelta(seconds=i * 5),
            user=u,
            ip_address="45.83.64.1",
        )
        for i, u in enumerate(users)
    ]


@pytest.fixture
def lateral_movement_events():
    """Network logons (type 3) to 3 distinct targets - triggers lateral-001."""
    from datetime import timedelta
    base = datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc)
    targets = ["ws01.corp.local", "ws02.corp.local", "ws03.corp.local"]
    return [
        make_event(
            4624,
            timestamp=base + timedelta(seconds=i * 30),
            computer=t,
            logon_type=3,
            ip_address="10.0.0.15",
        )
        for i, t in enumerate(targets)
    ]


@pytest.fixture
def critical_events():
    """Events that should auto-escalate to CRITICAL score."""
    return [
        make_event(1102),    # Audit log cleared
        make_event(5025),    # Firewall stopped
        make_event(4906),    # CrashOnAuditFail
        make_event(4794),    # DSRM password set
    ]


@pytest.fixture
def sample_csv_path(tmp_path) -> Path:
    """Write a minimal CSV log file and return its path."""
    path = tmp_path / "security.csv"
    rows = [
        {
            "Event ID": "4624",
            "Date and Time": "01/15/2026 09:00:01",
            "Source": "Microsoft-Windows-Security-Auditing",
            "Computer": "ws01.corp.local",
            "User": "jsmith",
            "Level": "Information",
            "Logon Type": "3",
            "Source Network Address": "10.0.0.15",
            "New Process Name": "",
            "Task Name": "",
            "Service Name": "",
            "Message": "An account was successfully logged on.",
        },
        {
            "Event ID": "4625",
            "Date and Time": "01/15/2026 09:01:00",
            "Source": "Microsoft-Windows-Security-Auditing",
            "Computer": "ws01.corp.local",
            "User": "admin",
            "Level": "Information",
            "Logon Type": "3",
            "Source Network Address": "185.220.101.1",
            "New Process Name": "",
            "Task Name": "",
            "Service Name": "",
            "Message": "An account failed to log on.",
        },
        {
            "Event ID": "1102",
            "Date and Time": "01/15/2026 09:25:00",
            "Source": "Microsoft-Windows-Security-Auditing",
            "Computer": "ws01.corp.local",
            "User": "jsmith",
            "Level": "Information",
            "Logon Type": "",
            "Source Network Address": "",
            "New Process Name": "",
            "Task Name": "",
            "Service Name": "",
            "Message": "The audit log was cleared.",
        },
    ]
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=rows[0].keys())
        writer.writeheader()
        writer.writerows(rows)
    return path


@pytest.fixture
def sample_jsonl_path(tmp_path) -> Path:
    """Write a minimal JSONL Security event file and return its path."""
    path = tmp_path / "events.json"
    events = [
        {"EventID": 4624, "EventTime": "2026-01-15 09:00:01",
         "Channel": "Security", "Hostname": "ws01.corp.local",
         "SourceName": "Microsoft-Windows-Security-Auditing",
         "SubjectUserName": "jsmith", "LogonType": "3",
         "IpAddress": "10.0.0.15", "Severity": "INFO", "Message": "Logon"},
        {"EventID": 1102, "EventTime": "2026-01-15 09:25:00",
         "Channel": "Security", "Hostname": "ws01.corp.local",
         "SourceName": "Microsoft-Windows-Security-Auditing",
         "Severity": "INFO", "Message": "Audit log cleared"},
    ]
    with open(path, "w", encoding="utf-8") as f:
        for e in events:
            f.write(_json.dumps(e) + "\n")
    return path


@pytest.fixture
def sample_alerts(brute_force_events, critical_events):
    """Pre-built alert list for report generator tests."""
    from src.detector import run_all_detections
    from src.mitre_mapper import map_many
    from src.risk_scorer import score_all
    events = brute_force_events + critical_events
    alerts = run_all_detections(events)
    alerts = score_all(alerts)
    alerts = map_many(alerts)
    return alerts
