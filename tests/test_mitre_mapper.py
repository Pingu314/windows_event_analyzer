"""Tests for src.mitre_mapper - technique mapping and tag hygiene."""
from __future__ import annotations

from src.detector import run_all_detections
from src.mitre_mapper import map_many, map_to_mitre
from tests.conftest import make_event


def test_primary_technique_from_rule(brute_force_events):
    alerts = run_all_detections(brute_force_events)
    alert = next(a for a in alerts if a["rule_id"] == "brute-001")
    tags = map_to_mitre(alert)
    assert tags[0] == "T1110.001 - Password Guessing"
    assert "T1078 - Valid Accounts" in tags


def test_tags_are_deduplicated(spray_events):
    alerts = run_all_detections(spray_events)
    alert = next(a for a in alerts if a["rule_id"] == "brute-002")
    tags = map_to_mitre(alert)
    assert len(tags) == len(set(tags))


def test_privileged_group_add_maps_to_t1098_007():
    event = make_event(4732, raw={"TargetUserName": "Domain Admins"})
    alerts = run_all_detections([event])
    alert = next(a for a in alerts if a["rule_id"] == "group-001")
    tags = map_to_mitre(alert)
    assert any(t.startswith("T1098.007") for t in tags)
    # regression: must not map to the cloud-credentials sub-technique
    assert not any(t.startswith("T1098.001") for t in tags)


def test_unknown_technique_id_passes_through():
    alert = {"rule_id": "x", "mitre": "T9999", "sigma_severity": "low",
             "detail": "", "event_ids": []}
    assert map_to_mitre(alert) == ["T9999"]


def test_detail_based_context():
    alert = {"rule_id": "x", "mitre": "", "sigma_severity": "low",
             "detail": "RDP logon from tor exit, kerberoast rc4", "event_ids": []}
    tags = map_to_mitre(alert)
    assert "T1021.001 - Remote Desktop Protocol" in tags
    assert "T1558.003 - Kerberoasting" in tags


def test_defender_detail_maps_to_disable_tools():
    alert = {"rule_id": "evasion-020", "mitre": "T1562.001",
             "sigma_severity": "critical",
             "detail": "Windows Defender audit policy disabled", "event_ids": [4719]}
    tags = map_to_mitre(alert)
    assert "T1562.001 - Disable or Modify Tools" in tags


def test_map_many_adds_tags(brute_force_events):
    alerts = run_all_detections(brute_force_events)
    mapped = map_many(alerts)
    assert all("mitre_tags" in a and a["mitre_tags"] for a in mapped)
