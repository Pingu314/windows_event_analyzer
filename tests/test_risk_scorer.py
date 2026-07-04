"""Tests for src.risk_scorer - scoring, severity tiers, escalation."""
from __future__ import annotations

from src.detector import run_all_detections
from src.risk_scorer import get_severity, score, score_all
from tests.conftest import make_event


def test_critical_event_auto_escalates(critical_events):
    alerts = run_all_detections(critical_events)
    for alert in alerts:
        risk = score(alert)
        assert risk["score"] == 100
        assert risk["severity"] == "CRITICAL"
        assert risk["breakdown"] == {"critical_auto_escalation": 100}


def test_brute_force_weighted_score(brute_force_events):
    alerts = run_all_detections(brute_force_events)
    alert = next(a for a in alerts if a["rule_id"] == "brute-001")
    risk = score(alert)
    # brute_force weight 25 + count bonus (5-1)*3 = 12
    assert risk["score"] == 37
    assert risk["severity"] == "MEDIUM"
    assert risk["breakdown"]["brute_force"] == 25
    assert risk["breakdown"]["count_bonus"] == 12


def test_count_bonus_is_capped():
    alert = {"rule_id": "brute-001", "sigma_severity": "high",
             "event_ids": [4625], "count": 100}
    risk = score(alert)
    assert risk["breakdown"]["count_bonus"] == 20


def test_unknown_rule_scores_zero():
    alert = {"rule_id": "nope-999", "sigma_severity": "low",
             "event_ids": [], "count": 1}
    risk = score(alert)
    assert risk["score"] == 0
    assert risk["severity"] == "LOW"


def test_score_never_exceeds_max():
    alert = {"rule_id": "lateral-003", "sigma_severity": "high",
             "event_ids": [4768, 4769], "count": 50}
    assert score(alert)["score"] <= 100


def test_score_all_adds_risk_key(brute_force_events):
    alerts = run_all_detections(brute_force_events)
    scored = score_all(alerts)
    assert all("risk" in a for a in scored)


def test_severity_boundaries():
    assert get_severity(100) == "CRITICAL"
    assert get_severity(80) == "CRITICAL"
    assert get_severity(79) == "HIGH"
    assert get_severity(50) == "HIGH"
    assert get_severity(49) == "MEDIUM"
    assert get_severity(25) == "MEDIUM"
    assert get_severity(24) == "LOW"
    assert get_severity(0) == "LOW"


def test_sigma_critical_rule_escalates_even_without_critical_event_id():
    # replay-001 has sigma_severity 'critical'
    alerts = run_all_detections([make_event(4649)])
    alert = next(a for a in alerts if a["rule_id"] == "replay-001")
    assert score(alert)["score"] == 100
