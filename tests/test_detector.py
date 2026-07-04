"""Tests for src.detector - detection rules, clustering and deduplication."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from src.detector import (
    RULES,
    _deduplicate,
    _is_ip,
    _matches_service_pattern,
    _sliding_window_clusters,
    run_all_detections,
)
from tests.conftest import make_event, make_events

BASE = datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc)  # Thursday 09:00


def rule_ids(alerts):
    return [a["rule_id"] for a in alerts]


# ---------------------------------------------------------------------------
# Registry sanity
# ---------------------------------------------------------------------------


def test_rule_registry_has_94_unique_rules():
    ids = [r["rule_id"] for r in RULES]
    assert len(ids) == 94
    assert len(set(ids)) == 94


def test_no_events_no_alerts():
    assert run_all_detections([]) == []


def test_benign_logon_produces_no_alerts():
    # Normal interactive logon during business hours, standard user
    event = make_event(4624, timestamp=BASE, logon_type=2, user="jsmith")
    assert run_all_detections([event]) == []


# ---------------------------------------------------------------------------
# Threshold rules
# ---------------------------------------------------------------------------


def test_brute_force_single_burst_single_alert(brute_force_events):
    alerts = run_all_detections(brute_force_events)
    assert rule_ids(alerts).count("brute-001") == 1
    alert = next(a for a in alerts if a["rule_id"] == "brute-001")
    assert alert["count"] == 5
    assert alert["ip"] == "185.220.101.1"


def test_brute_force_long_burst_still_single_alert():
    # Regression: overlapping sliding windows used to emit one alert per
    # start offset (6 alerts for a 10-event burst).
    events = make_events(4625, count=10, interval_seconds=5,
                         ip_address="1.2.3.4", user="admin")
    alerts = run_all_detections(events)
    assert rule_ids(alerts).count("brute-001") == 1


def test_brute_force_below_threshold_no_alert():
    events = make_events(4625, count=3, ip_address="1.2.3.4", user="admin")
    alerts = run_all_detections(events)
    assert "brute-001" not in rule_ids(alerts)


def test_password_spray(spray_events):
    alerts = run_all_detections(spray_events)
    spray = [a for a in alerts if a["rule_id"] == "brute-002"]
    assert len(spray) == 1
    assert "4 accounts" in spray[0]["detail"]


def test_lateral_movement(lateral_movement_events):
    alerts = run_all_detections(lateral_movement_events)
    lateral = [a for a in alerts if a["rule_id"] == "lateral-001"]
    assert len(lateral) == 1
    assert "3 targets" in lateral[0]["detail"]


def test_mass_lockout():
    events = [
        make_event(4740, timestamp=BASE + timedelta(seconds=i * 10), user=u)
        for i, u in enumerate(["alice", "bob", "carol", "dave"])
    ]
    alerts = run_all_detections(events)
    assert rule_ids(alerts).count("lockout-002") == 1
    # one lockout-001 per locked account, no duplicates
    assert rule_ids(alerts).count("lockout-001") == 4


def test_single_lockout_no_duplicate_alert():
    # Regression: 4740 used to fire lockout-001 twice (single-event map +
    # dedicated detector) with different detail strings.
    alerts = run_all_detections([make_event(4740, user="bob")])
    assert rule_ids(alerts) == ["lockout-001"]


def test_account_enumeration():
    users = ["ghost1", "ghost2", "ghost3", "ghost4", "ghost5"]
    events = [
        make_event(4625, timestamp=BASE + timedelta(seconds=i * 10), user=u,
                   ip_address="45.83.64.9", raw={"SubStatus": "0xC0000064"})
        for i, u in enumerate(users)
    ]
    alerts = run_all_detections(events)
    assert "recon-003" in rule_ids(alerts)


def test_rdp_reconnect_anomaly_single_alert():
    events = make_events(4778, count=3, interval_seconds=60, user="jsmith")
    alerts = run_all_detections(events)
    assert rule_ids(alerts).count("logon-005") == 1


def test_firewall_change_burst():
    events = [
        make_event(eid, timestamp=BASE + timedelta(seconds=i * 20))
        for i, eid in enumerate([4946, 4947, 4948])
    ]
    alerts = run_all_detections(events)
    burst = [a for a in alerts if a["rule_id"] == "evasion-008" and a["count"] == 3]
    assert len(burst) == 1


# ---------------------------------------------------------------------------
# Logon-type rules
# ---------------------------------------------------------------------------


def test_rdp_logon():
    alerts = run_all_detections(
        [make_event(4624, logon_type=10, ip_address="10.0.0.99")])
    assert "logon-002" in rule_ids(alerts)


def test_runas_netonly():
    alerts = run_all_detections([make_event(4624, logon_type=9)])
    assert "lateral-009" in rule_ids(alerts)


def test_off_hours_logon_weekend():
    saturday = datetime(2026, 1, 17, 10, 0, 0, tzinfo=timezone.utc)
    alerts = run_all_detections([make_event(4624, timestamp=saturday)])
    assert "logon-004" in rule_ids(alerts)


def test_off_hours_logon_night():
    night = datetime(2026, 1, 15, 23, 30, 0, tzinfo=timezone.utc)
    alerts = run_all_detections([make_event(4624, timestamp=night)])
    assert "logon-004" in rule_ids(alerts)


def test_service_account_interactive_logon():
    alerts = run_all_detections(
        [make_event(4624, logon_type=2, user="svc_backup")])
    assert "logon-007" in rule_ids(alerts)


def test_regular_user_ending_in_sa_not_flagged_as_service_account():
    # Regression: 'lisa' used to match the stripped 'sa-' pattern.
    alerts = run_all_detections([make_event(4624, logon_type=2, user="lisa")])
    assert "logon-007" not in rule_ids(alerts)


def test_matches_service_pattern():
    assert _matches_service_pattern("svc_sql")
    assert _matches_service_pattern("backup_svc")
    assert not _matches_service_pattern("lisa")
    assert not _matches_service_pattern("teresa")


# ---------------------------------------------------------------------------
# Sequence rules
# ---------------------------------------------------------------------------


def test_privilege_escalation_sequence():
    events = [
        make_event(4624, timestamp=BASE, user="attacker"),
        make_event(4672, timestamp=BASE + timedelta(seconds=10), user="attacker"),
    ]
    alerts = run_all_detections(events)
    assert "priv-004" in rule_ids(alerts)


def test_pass_the_ticket():
    events = [
        make_event(4768, timestamp=BASE, user="victim"),
        make_event(4769, timestamp=BASE + timedelta(minutes=2), user="victim"),
    ]
    alerts = run_all_detections(events)
    assert "lateral-003" in rule_ids(alerts)


def test_explicit_credential_then_network_logon():
    events = [
        make_event(4648, timestamp=BASE, user="attacker"),
        make_event(4624, timestamp=BASE + timedelta(seconds=30),
                   user="attacker", logon_type=3),
    ]
    alerts = run_all_detections(events)
    assert "lateral-007" in rule_ids(alerts)


def test_audit_policy_then_log_clear_sequence():
    events = [
        make_event(4719, timestamp=BASE),
        make_event(1102, timestamp=BASE + timedelta(minutes=1)),
    ]
    alerts = run_all_detections(events)
    ids = rule_ids(alerts)
    assert "evasion-019" in ids
    assert "evasion-001" in ids


def test_registry_mod_then_process_creation():
    events = [
        make_event(4657, timestamp=BASE, user="attacker"),
        make_event(4688, timestamp=BASE + timedelta(seconds=5),
                   user="attacker", process_name="evil.exe"),
    ]
    alerts = run_all_detections(events)
    assert "exec-005" in rule_ids(alerts)


def test_short_lived_process():
    events = [
        make_event(4688, timestamp=BASE, process_name="dropper.exe",
                   raw={"NewProcessId": "0x1a2b"}),
        make_event(4689, timestamp=BASE + timedelta(seconds=4),
                   raw={"ProcessId": "0x1a2b"}),
    ]
    alerts = run_all_detections(events)
    assert "exec-003" in rule_ids(alerts)


# ---------------------------------------------------------------------------
# Process & execution
# ---------------------------------------------------------------------------


def test_known_malicious_process():
    alerts = run_all_detections(
        [make_event(4688, process_name="mimikatz.exe")])
    assert "exec-006" in rule_ids(alerts)


def test_suspicious_parent_child():
    event = make_event(
        4688, process_name="powershell.exe",
        raw={"ParentProcessName": "C:\\Program Files\\Office\\WINWORD.EXE"})
    alerts = run_all_detections([event])
    assert "exec-001" in rule_ids(alerts)


def test_suspicious_cmdline():
    event = make_event(
        4688, process_name="powershell.exe",
        raw={"CommandLine": "powershell.exe -enc SQBFAFgA -windowstyle hidden"})
    alerts = run_all_detections([event])
    assert "exec-002" in rule_ids(alerts)


def test_sensitive_file_access_is_critical():
    event = make_event(
        4663, raw={"ObjectName": "C:\\Windows\\System32\\config\\SAM"})
    alerts = run_all_detections([event])
    exec7 = next(a for a in alerts if a["rule_id"] == "exec-007")
    assert exec7["sigma_severity"] == "critical"


# ---------------------------------------------------------------------------
# Persistence & evasion
# ---------------------------------------------------------------------------


def test_scheduled_task_created():
    alerts = run_all_detections(
        [make_event(4698, task_name="\\Microsoft\\Windows\\EvilTask")])
    assert "persist-001" in rule_ids(alerts)


def test_registry_autorun_key():
    event = make_event(
        4657,
        raw={"ObjectName":
             "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\x"})
    alerts = run_all_detections([event])
    assert "persist-011" in rule_ids(alerts)


def test_service_install_suspicious_path_single_alert():
    # Regression: suspicious-path installs used to fire persist-005 twice.
    event = make_event(
        4697, raw={"ImagePath": "C:\\Users\\bob\\AppData\\Local\\evil.exe"})
    alerts = run_all_detections([event])
    persist = [a for a in alerts if a["rule_id"] == "persist-005"]
    assert len(persist) == 1
    assert "suspicious path" in persist[0]["detail"]


def test_service_install_normal_path_generic_alert():
    event = make_event(
        4697, service_name="GoodSvc",
        raw={"ImagePath": "C:\\Windows\\System32\\goodsvc.exe"})
    alerts = run_all_detections([event])
    persist = [a for a in alerts if a["rule_id"] == "persist-005"]
    assert len(persist) == 1
    assert "suspicious path" not in persist[0]["detail"]


def test_defender_audit_policy_disabled():
    event = make_event(
        4719,
        raw={"SubcategoryGuid": "{0CCE9248-69AE-11D9-BED3-505054503030}"})
    alerts = run_all_detections([event])
    assert "evasion-020" in rule_ids(alerts)


def test_sensitive_permission_change():
    event = make_event(4670, raw={"ObjectName": "C:\\Windows\\NTDS\\ntds.dit"})
    alerts = run_all_detections([event])
    assert "evasion-017" in rule_ids(alerts)


def test_privileged_group_member_added():
    event = make_event(4732, raw={"TargetUserName": "Administrators"})
    alerts = run_all_detections([event])
    assert "group-001" in rule_ids(alerts)


def test_unprivileged_group_change_not_alerted():
    event = make_event(4732, raw={"TargetUserName": "Book Club"})
    alerts = run_all_detections([event])
    assert "group-001" not in rule_ids(alerts)


# ---------------------------------------------------------------------------
# Lateral movement
# ---------------------------------------------------------------------------


def test_kerberoasting_rc4():
    event = make_event(4769, raw={"TicketEncryptionType": "0x17"})
    alerts = run_all_detections([event])
    assert "lateral-008" in rule_ids(alerts)


def test_kerberos_aes_ticket_not_flagged():
    event = make_event(4769, raw={"TicketEncryptionType": "0x12"})
    alerts = run_all_detections([event])
    assert "lateral-008" not in rule_ids(alerts)


def test_ntlm_relay_to_self_flagged():
    event = make_event(
        4624, logon_type=3, ip_address="10.0.0.5", computer="fs01",
        raw={"AuthenticationPackageName": "NTLM", "WorkstationName": "FS01"})
    alerts = run_all_detections([event])
    assert "lateral-010" in rule_ids(alerts)


def test_normal_remote_ntlm_logon_not_flagged():
    # Regression: every NTLM network logon used to be flagged as a relay.
    event = make_event(
        4624, logon_type=3, ip_address="10.0.0.5", computer="fs01",
        raw={"AuthenticationPackageName": "NTLM", "WorkstationName": "WS02"})
    alerts = run_all_detections([event])
    assert "lateral-010" not in rule_ids(alerts)


# ---------------------------------------------------------------------------
# Critical escalation and single-event rules
# ---------------------------------------------------------------------------


def test_critical_events_escalate_sigma_severity(critical_events):
    alerts = run_all_detections(critical_events)
    assert alerts
    assert all(a["sigma_severity"] == "critical" for a in alerts)


def test_single_event_rules_sample():
    events = [
        make_event(4720),   # acct-001 new account
        make_event(4104),   # exec-004 scriptblock
        make_event(4798),   # recon-001 group enumeration
    ]
    ids = rule_ids(run_all_detections(events))
    assert {"acct-001", "exec-004", "recon-001"} <= set(ids)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def test_sliding_window_clusters_non_overlapping():
    events = make_events(4625, count=10, interval_seconds=5)
    clusters = _sliding_window_clusters(events, timedelta(minutes=5), 5)
    assert len(clusters) == 1
    assert len(clusters[0]) == 10


def test_sliding_window_two_separate_bursts():
    burst1 = make_events(4625, count=5, interval_seconds=5)
    burst2 = make_events(4625, count=5, interval_seconds=5,
                         base_time=BASE + timedelta(hours=2))
    clusters = _sliding_window_clusters(
        burst1 + burst2, timedelta(minutes=5), 5)
    assert len(clusters) == 2


def test_deduplicate():
    alert = {"rule_id": "x", "computer": "ws01", "user": "a", "detail": "d"}
    assert len(_deduplicate([alert, dict(alert)])) == 1


def test_is_ip():
    assert _is_ip("192.168.1.1")
    assert not _is_ip("ws01.corp.local")
    assert not _is_ip("")
    assert not _is_ip(None)
