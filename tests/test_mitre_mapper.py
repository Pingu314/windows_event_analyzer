"""Tests for src.mitre_mapper - technique mapping and tag hygiene."""
from __future__ import annotations

import pytest

from src.detector import RULES, run_all_detections
from src.mitre_mapper import _TECHNIQUE_NAMES, map_many, map_to_mitre
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


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r["rule_id"])
def test_every_rule_produces_valid_tags(rule):
    """Every rule's primary + contextual techniques resolve to known labels."""
    alert = {
        "rule_id": rule["rule_id"],
        "mitre": rule["mitre"],
        "sigma_severity": rule["sigma_severity"],
        "detail": "",
        "event_ids": rule["event_ids"],
    }
    tags = map_to_mitre(alert)
    assert tags, f"{rule['rule_id']} produced no tags"
    assert rule["mitre"] in _TECHNIQUE_NAMES, (
        f"{rule['rule_id']} primary technique {rule['mitre']} "
        f"missing from _TECHNIQUE_NAMES")
    for tag in tags:
        assert tag in _TECHNIQUE_NAMES.values(), (
            f"{rule['rule_id']} produced unmapped tag {tag}")


def test_detail_keyword_branches():
    """Exercise the detail-based contextual mapping branches."""
    details = {
        "kerberos ticket issued": "T1558",
        "smb share accessed": "T1021.002",
        "password spray detected": "T1110.003",
        "lateral movement to 3 targets": "T1021",
        "suspicious cmdline keywords: powershell": "T1059.001",
        "registry autorun key modified": "T1547.001",
        "scheduled task: evil": "T1053.005",
        "firewall rule deleted": "T1562.004",
        "wmi subscription created": "T1546.003",
        "sensitive file accessed: ntds.dit": "T1003",
        "downloadstring in cmdline": "T1105",
        "encodedcommand used": "T1027",
        "cmd.exe spawned": "T1059.003",
        "invoke-webrequest to c2": "T1071.001",
        "ntlm relay indicator": "T1557.001",
    }
    for detail, technique in details.items():
        alert = {"rule_id": "x", "mitre": "", "sigma_severity": "low",
                 "detail": detail, "event_ids": []}
        tags = map_to_mitre(alert)
        assert any(t.startswith(technique) for t in tags), (
            f"detail '{detail}' did not map to {technique}: {tags}")
