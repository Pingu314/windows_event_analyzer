"""Tests for src.sigma_loader and Sigma rule execution in the detector."""
from __future__ import annotations

from pathlib import Path

from src.detector import run_all_detections
from src.risk_scorer import score
from src.sigma_loader import convert_sigma_rule, load_sigma_rules
from tests.conftest import make_event

BUNDLED = Path(__file__).resolve().parent.parent / "rules" / "sigma"


def test_load_bundled_rules():
    rules = load_sigma_rules(BUNDLED)
    assert len(rules) == 3
    for rule in rules:
        assert rule["rule_id"].startswith("sigma-")
        assert rule["category"] == "Sigma"
        assert rule["match"]["event_ids"]


def test_load_nonexistent_path_returns_empty(tmp_path):
    assert load_sigma_rules(tmp_path / "nope") == []


def test_malformed_yaml_is_skipped(tmp_path):
    (tmp_path / "broken.yml").write_text("title: [unclosed")
    (tmp_path / "notdict.yml").write_text("- just\n- a list\n")
    assert load_sigma_rules(tmp_path) == []


def test_unsupported_condition_is_skipped():
    doc = {
        "title": "complex",
        "detection": {
            "selection": {"EventID": 4688},
            "filter": {"User": "x"},
            "condition": "selection and not filter",
        },
    }
    assert convert_sigma_rule(doc) is None


def test_selection_without_event_id_is_skipped():
    doc = {"title": "no-eid",
           "detection": {"selection": {"CommandLine|contains": "x"},
                         "condition": "selection"}}
    assert convert_sigma_rule(doc) is None


def test_unsupported_modifier_is_skipped():
    doc = {"title": "regex",
           "detection": {"selection": {"EventID": 4688,
                                       "CommandLine|re": ".*"},
                         "condition": "selection"}}
    assert convert_sigma_rule(doc) is None


def test_convert_extracts_technique_and_level():
    doc = {
        "title": "Test Rule", "id": "abc-123", "level": "high",
        "tags": ["attack.execution", "attack.t1059.001"],
        "detection": {"selection": {"EventID": [4688, 4104],
                                    "CommandLine|contains": ["iex"]},
                      "condition": "selection"},
    }
    rule = convert_sigma_rule(doc)
    assert rule["mitre"] == "T1059.001"
    assert rule["sigma_severity"] == "high"
    assert rule["event_ids"] == [4688, 4104]
    assert rule["match"]["contains"] == {"CommandLine": ["iex"]}


def test_sigma_rule_fires_on_matching_event():
    rules = load_sigma_rules(BUNDLED)
    event = make_event(
        4688, process_name="wevtutil.exe",
        raw={"CommandLine": "wevtutil cl Security"})
    alerts = run_all_detections([event], sigma_rules=rules)
    sigma_alerts = [a for a in alerts if a["rule_id"].startswith("sigma-")]
    assert len(sigma_alerts) == 1
    assert "wevtutil" in sigma_alerts[0]["detail"].lower() or \
        "event log cleared" in sigma_alerts[0]["rule"].lower()


def test_sigma_rule_does_not_fire_on_non_matching_event():
    rules = load_sigma_rules(BUNDLED)
    event = make_event(4688, raw={"CommandLine": "notepad.exe report.txt"})
    alerts = run_all_detections([event], sigma_rules=rules)
    assert not any(a["rule_id"].startswith("sigma-") for a in alerts)


def test_sigma_equals_matching():
    rule = convert_sigma_rule({
        "title": "exact", "level": "medium",
        "detection": {"selection": {"EventID": 4624, "LogonType": 3},
                      "condition": "selection"},
    })
    hit = make_event(4624, logon_type=3, raw={"LogonType": "3"})
    miss = make_event(4624, logon_type=2, raw={"LogonType": "2"})
    alerts = run_all_detections([hit, miss], sigma_rules=[rule])
    sigma_alerts = [a for a in alerts if a["rule_id"].startswith("sigma-")]
    assert len(sigma_alerts) == 1


def test_sigma_alert_scored_by_level():
    rules = load_sigma_rules(BUNDLED)
    event = make_event(4688, raw={"CommandLine": "whoami /all"})
    alerts = run_all_detections([event], sigma_rules=rules)
    whoami = next(a for a in alerts if a["rule_id"].startswith("sigma-")
                  and "whoami" in a["rule"].lower())
    risk = score(whoami)
    assert risk["breakdown"].get("sigma_level") == 15   # level: low
    assert risk["severity"] == "LOW"
