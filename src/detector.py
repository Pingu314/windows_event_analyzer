"""
detector.py - Windows Security Event Detector

Implements 94 SIGMA-style detection rules across 8 categories:
  - Authentication & Logon
  - Account Management
  - Privilege & Escalation
  - Persistence
  - Lateral Movement
  - Process & Execution
  - Defense Evasion
  - Active Directory

All rules return a standardised alert dict:
    {
        "rule_id":        str,
        "rule":           str,
        "category":       str,
        "mitre":          str,
        "sigma_severity": str,
        "event_ids":      list[int],
        "computer":       str,
        "user":           str | None,
        "ip":             str | None,
        "count":          int,
        "detail":         str,
        "events":         list[dict],   # triggering events
    }

CRITICAL events (see settings.CRITICAL_EVENT_IDS) auto-escalate
regardless of risk score.

DC-only events (settings.DC_ONLY_EVENT_IDS) are detected when present
and silently skipped when absent - no false alerts on non-DC systems.

Audit-policy-dependent events (4688, 4689, 4104) are detected when
present. A caveat is logged if none are found.
"""
from __future__ import annotations

import logging
import re
from collections import defaultdict
from datetime import timedelta
from pathlib import Path

from config.settings import (
    BRUTE_FORCE_THRESHOLD,
    BRUTE_FORCE_WINDOW_MINUTES,
    BUSINESS_DAYS,
    BUSINESS_HOURS_END,
    BUSINESS_HOURS_START,
    CRITICAL_EVENT_IDS,
    DC_ONLY_EVENT_IDS,
    FIREWALL_CHANGE_THRESHOLD,
    FIREWALL_CHANGE_WINDOW_MINUTES,
    KERBEROS_WINDOW_MINUTES,
    LATERAL_THRESHOLD,
    LATERAL_WINDOW_MINUTES,
    MPSSVC_SUBCATEGORY_GUID,
    PRIVILEGED_GROUPS,
    RDP_RECONNECT_THRESHOLD,
    RDP_RECONNECT_WINDOW_MINUTES,
    REQUIRES_OBJECT_ACCESS_AUDITING,
    REQUIRES_POWERSHELL_LOGGING,
    REQUIRES_PROCESS_AUDITING,
    SENSITIVE_FILE_PATHS,
    SENSITIVE_REGISTRY_PATHS,
    SERVICE_ACCOUNT_PATTERNS,
    SHORT_PROCESS_SECONDS,
    SPRAY_THRESHOLD,
    SPRAY_WINDOW_MINUTES,
    SUSPICIOUS_CMDLINE_KEYWORDS,
    SUSPICIOUS_PARENT_CHILD,
    SUSPICIOUS_PROCESSES,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Rule registry
# ---------------------------------------------------------------------------

RULES: list[dict] = [
    # Authentication & Logon
    {"rule_id": "brute-001", "rule": "Brute Force Login",
     "category": "Authentication", "mitre": "T1110.001",
     "sigma_severity": "high", "event_ids": [4625]},
    {"rule_id": "brute-002", "rule": "Password Spraying",
     "category": "Authentication", "mitre": "T1110.003",
     "sigma_severity": "high", "event_ids": [4625]},
    {"rule_id": "logon-001", "rule": "Suspicious Network Logon Sequence",
     "category": "Authentication", "mitre": "T1021",
     "sigma_severity": "medium", "event_ids": [4624]},
    {"rule_id": "logon-002", "rule": "Remote Interactive Logon (RDP)",
     "category": "Authentication", "mitre": "T1021.001",
     "sigma_severity": "medium", "event_ids": [4624]},
    {"rule_id": "logon-003", "rule": "Explicit Credential Use",
     "category": "Authentication", "mitre": "T1550.002",
     "sigma_severity": "high", "event_ids": [4648]},
    {"rule_id": "logon-004", "rule": "Off-Hours Logon",
     "category": "Authentication", "mitre": "T1078",
     "sigma_severity": "medium", "event_ids": [4624]},
    {"rule_id": "logon-005", "rule": "RDP Session Reconnect Anomaly",
     "category": "Authentication", "mitre": "T1021.001",
     "sigma_severity": "low", "event_ids": [4778]},
    {"rule_id": "logon-006", "rule": "RDP Session Disconnected",
     "category": "Authentication", "mitre": "T1021.001",
     "sigma_severity": "low", "event_ids": [4779]},
    {"rule_id": "logon-007", "rule": "Service Account Interactive Logon",
     "category": "Authentication", "mitre": "T1078.002",
     "sigma_severity": "high", "event_ids": [4624]},
    {"rule_id": "lockout-001", "rule": "Account Lockout",
     "category": "Authentication", "mitre": "T1110.001",
     "sigma_severity": "high", "event_ids": [4740]},
    {"rule_id": "lockout-002", "rule": "Mass Account Lockout",
     "category": "Authentication", "mitre": "T1110.003",
     "sigma_severity": "high", "event_ids": [4740]},
    {"rule_id": "replay-001", "rule": "Replay Attack Detected",
     "category": "Authentication", "mitre": "T1550",
     "sigma_severity": "critical", "event_ids": [4649]},
    {"rule_id": "special-001", "rule": "Special Groups Assigned at Logon",
     "category": "Authentication", "mitre": "T1078.003",
     "sigma_severity": "high", "event_ids": [4964]},

    # Account Management
    {"rule_id": "acct-001", "rule": "New User Account Created",
     "category": "Account Management", "mitre": "T1136.001",
     "sigma_severity": "high", "event_ids": [4720]},
    {"rule_id": "acct-002", "rule": "User Account Enabled",
     "category": "Account Management", "mitre": "T1098",
     "sigma_severity": "medium", "event_ids": [4722]},
    {"rule_id": "acct-003", "rule": "User Account Disabled",
     "category": "Account Management", "mitre": "T1531",
     "sigma_severity": "medium", "event_ids": [4725]},
    {"rule_id": "acct-004", "rule": "User Account Deleted",
     "category": "Account Management", "mitre": "T1531",
     "sigma_severity": "high", "event_ids": [4726]},
    {"rule_id": "acct-005", "rule": "User Account Changed",
     "category": "Account Management", "mitre": "T1098",
     "sigma_severity": "high", "event_ids": [4738]},
    {"rule_id": "acct-006", "rule": "User Account Locked Out",
     "category": "Account Management", "mitre": "T1110.001",
     "sigma_severity": "high", "event_ids": [4740]},
    {"rule_id": "acct-007", "rule": "User Account Unlocked",
     "category": "Account Management", "mitre": "T1098",
     "sigma_severity": "medium", "event_ids": [4767]},
    {"rule_id": "acct-008", "rule": "Account Renamed",
     "category": "Account Management", "mitre": "T1078",
     "sigma_severity": "high", "event_ids": [4781]},
    {"rule_id": "acct-009", "rule": "Password Change or Reset",
     "category": "Account Management", "mitre": "T1098",
     "sigma_severity": "medium", "event_ids": [4723, 4724]},
    {"rule_id": "acct-010", "rule": "DSRM Password Set Attempt",
     "category": "Account Management", "mitre": "T1003.002",
     "sigma_severity": "critical", "event_ids": [4794]},
    {"rule_id": "group-001", "rule": "Member Added to Privileged Group",
     "category": "Account Management", "mitre": "T1098.001",
     "sigma_severity": "high", "event_ids": [4732, 4728, 4756]},
    {"rule_id": "group-002", "rule": "Member Removed from Privileged Group",
     "category": "Account Management", "mitre": "T1098.001",
     "sigma_severity": "medium", "event_ids": [4733, 4729, 4757]},
    {"rule_id": "group-003", "rule": "Security Group Changed",
     "category": "Account Management", "mitre": "T1098",
     "sigma_severity": "high", "event_ids": [4735, 4737, 4755]},
    {"rule_id": "group-004", "rule": "SID History Added to Account",
     "category": "Account Management", "mitre": "T1134.005",
     "sigma_severity": "critical", "event_ids": [4765]},
    {"rule_id": "group-005", "rule": "SID History Add Attempt Failed",
     "category": "Account Management", "mitre": "T1134.005",
     "sigma_severity": "high", "event_ids": [4766]},
    {"rule_id": "group-006", "rule": "Shadow Admin ACL Set",
     "category": "Account Management", "mitre": "T1098",
     "sigma_severity": "high", "event_ids": [4780]},
    {"rule_id": "recon-001", "rule": "Local Group Membership Enumerated",
     "category": "Account Management", "mitre": "T1069.001",
     "sigma_severity": "medium", "event_ids": [4798]},
    {"rule_id": "recon-002", "rule": "Security Group Membership Enumerated",
     "category": "Account Management", "mitre": "T1069.001",
     "sigma_severity": "medium", "event_ids": [4799]},
    {"rule_id": "recon-003", "rule": "Account Enumeration via Failed Logons",
     "category": "Account Management", "mitre": "T1087.002",
     "sigma_severity": "medium", "event_ids": [4625]},

    # Privilege & Escalation
    {"rule_id": "priv-001", "rule": "Special Privileges Assigned at Logon",
     "category": "Privilege Escalation", "mitre": "T1078.003",
     "sigma_severity": "high", "event_ids": [4672]},
    {"rule_id": "priv-002", "rule": "Privileged Service Called",
     "category": "Privilege Escalation", "mitre": "T1078.003",
     "sigma_severity": "medium", "event_ids": [4673]},
    {"rule_id": "priv-003", "rule": "Operation on Privileged Object",
     "category": "Privilege Escalation", "mitre": "T1068",
     "sigma_severity": "medium", "event_ids": [4674]},
    {"rule_id": "priv-004", "rule": "Privilege Escalation After New Logon",
     "category": "Privilege Escalation", "mitre": "T1068",
     "sigma_severity": "high", "event_ids": [4624, 4672]},
    {"rule_id": "priv-005", "rule": "Token Right Adjusted",
     "category": "Privilege Escalation", "mitre": "T1134",
     "sigma_severity": "high", "event_ids": [4703]},
    {"rule_id": "priv-006", "rule": "User Right Assigned",
     "category": "Privilege Escalation", "mitre": "T1134.001",
     "sigma_severity": "high", "event_ids": [4704]},
    {"rule_id": "priv-007", "rule": "User Right Removed",
     "category": "Privilege Escalation", "mitre": "T1134.001",
     "sigma_severity": "medium", "event_ids": [4705]},

    # Persistence
    {"rule_id": "persist-001", "rule": "Scheduled Task Created",
     "category": "Persistence", "mitre": "T1053.005",
     "sigma_severity": "high", "event_ids": [4698]},
    {"rule_id": "persist-002", "rule": "Scheduled Task Modified",
     "category": "Persistence", "mitre": "T1053.005",
     "sigma_severity": "high", "event_ids": [4702]},
    {"rule_id": "persist-003", "rule": "Scheduled Task Deleted",
     "category": "Persistence", "mitre": "T1053.005",
     "sigma_severity": "medium", "event_ids": [4699]},
    {"rule_id": "persist-004", "rule": "Scheduled Task Enabled",
     "category": "Persistence", "mitre": "T1053.005",
     "sigma_severity": "medium", "event_ids": [4700]},
    {"rule_id": "persist-005", "rule": "Service Installed",
     "category": "Persistence", "mitre": "T1543.003",
     "sigma_severity": "high", "event_ids": [4697, 7045]},
    {"rule_id": "persist-006", "rule": "Registry Value Modified",
     "category": "Persistence", "mitre": "T1112",
     "sigma_severity": "medium", "event_ids": [4657]},
    {"rule_id": "persist-007", "rule": "New Domain Trust Created",
     "category": "Persistence", "mitre": "T1484.002",
     "sigma_severity": "high", "event_ids": [4706]},
    {"rule_id": "persist-008", "rule": "External Device Recognized",
     "category": "Persistence", "mitre": "T1052.001",
     "sigma_severity": "medium", "event_ids": [6416]},
    {"rule_id": "persist-009", "rule": "Certificate Request Received",
     "category": "Persistence", "mitre": "T1553.004",
     "sigma_severity": "medium", "event_ids": [4886]},
    {"rule_id": "persist-010", "rule": "Certificate Request Approved",
     "category": "Persistence", "mitre": "T1553.004",
     "sigma_severity": "high", "event_ids": [4887]},
    {"rule_id": "persist-011", "rule": "Registry Autorun Key Modified",
     "category": "Persistence", "mitre": "T1547.001",
     "sigma_severity": "high", "event_ids": [4657]},
    {"rule_id": "persist-012", "rule": "WMI Event Subscription Created",
     "category": "Persistence", "mitre": "T1546.003",
     "sigma_severity": "high", "event_ids": [5861]},
    {"rule_id": "persist-013", "rule": "Security Support Provider Loaded",
     "category": "Persistence", "mitre": "T1547.005",
     "sigma_severity": "high", "event_ids": [4610]},

    # Lateral Movement
    {"rule_id": "lateral-001", "rule": "Lateral Movement Network Logon Sequence",
     "category": "Lateral Movement", "mitre": "T1021",
     "sigma_severity": "high", "event_ids": [4624]},
    {"rule_id": "lateral-002", "rule": "Kerberos Pre-Auth Failure",
     "category": "Lateral Movement", "mitre": "T1558.003",
     "sigma_severity": "high", "event_ids": [4771]},
    {"rule_id": "lateral-003", "rule": "Pass-the-Ticket Detected",
     "category": "Lateral Movement", "mitre": "T1550.003",
     "sigma_severity": "high", "event_ids": [4768, 4769]},
    {"rule_id": "lateral-004", "rule": "NTLM Authentication Attempt",
     "category": "Lateral Movement", "mitre": "T1550.002",
     "sigma_severity": "medium", "event_ids": [4776]},
    {"rule_id": "lateral-005", "rule": "SMB Network Share Accessed",
     "category": "Lateral Movement", "mitre": "T1021.002",
     "sigma_severity": "medium", "event_ids": [5140]},
    {"rule_id": "lateral-006", "rule": "SMB Share Enumeration",
     "category": "Lateral Movement", "mitre": "T1135",
     "sigma_severity": "medium", "event_ids": [5145]},
    {"rule_id": "lateral-007", "rule": "Explicit Credential Use Followed by Network Logon",
     "category": "Lateral Movement", "mitre": "T1550.002",
     "sigma_severity": "high", "event_ids": [4648, 4624]},
    {"rule_id": "lateral-008", "rule": "Kerberoasting - RC4 Encryption Downgrade",
     "category": "Lateral Movement", "mitre": "T1558.003",
     "sigma_severity": "high", "event_ids": [4769]},
    {"rule_id": "lateral-009", "rule": "New Credentials Logon (runas /netonly)",
     "category": "Lateral Movement", "mitre": "T1550.002",
     "sigma_severity": "medium", "event_ids": [4624]},
    {"rule_id": "lateral-010", "rule": "NTLM Relay Indicator",
     "category": "Lateral Movement", "mitre": "T1557.001",
     "sigma_severity": "high", "event_ids": [4624]},

    # Process & Execution
    {"rule_id": "exec-001", "rule": "Suspicious Process Parent-Child",
     "category": "Execution", "mitre": "T1059",
     "sigma_severity": "high", "event_ids": [4688]},
    {"rule_id": "exec-002", "rule": "Suspicious Command Line",
     "category": "Execution", "mitre": "T1059.001",
     "sigma_severity": "high", "event_ids": [4688]},
    {"rule_id": "exec-003", "rule": "Short-Lived Process",
     "category": "Execution", "mitre": "T1059",
     "sigma_severity": "medium", "event_ids": [4688, 4689]},
    {"rule_id": "exec-004", "rule": "PowerShell Script Block Logged",
     "category": "Execution", "mitre": "T1059.001",
     "sigma_severity": "high", "event_ids": [4104]},
    {"rule_id": "exec-005", "rule": "Registry Modification Before Process Creation",
     "category": "Execution", "mitre": "T1112",
     "sigma_severity": "high", "event_ids": [4657, 4688]},
    {"rule_id": "exec-006", "rule": "Known Malicious Process Name",
     "category": "Execution", "mitre": "T1059",
     "sigma_severity": "high", "event_ids": [4688]},
    {"rule_id": "exec-007", "rule": "Sensitive File Access by Process",
     "category": "Execution", "mitre": "T1003.002",
     "sigma_severity": "critical", "event_ids": [4663]},

    # Defense Evasion
    {"rule_id": "evasion-001", "rule": "Audit Log Cleared",
     "category": "Defense Evasion", "mitre": "T1070.001",
     "sigma_severity": "critical", "event_ids": [1102]},
    {"rule_id": "evasion-002", "rule": "System Audit Policy Changed",
     "category": "Defense Evasion", "mitre": "T1562.002",
     "sigma_severity": "high", "event_ids": [4719]},
    {"rule_id": "evasion-003", "rule": "CrashOnAuditFail Changed",
     "category": "Defense Evasion", "mitre": "T1562.002",
     "sigma_severity": "critical", "event_ids": [4906]},
    {"rule_id": "evasion-004", "rule": "System Time Changed",
     "category": "Defense Evasion", "mitre": "T1070.006",
     "sigma_severity": "high", "event_ids": [4616]},
    {"rule_id": "evasion-005", "rule": "Trusted Domain Modified",
     "category": "Defense Evasion", "mitre": "T1484.002",
     "sigma_severity": "high", "event_ids": [4716]},
    {"rule_id": "evasion-006", "rule": "Firewall Rule Added",
     "category": "Defense Evasion", "mitre": "T1562.004",
     "sigma_severity": "medium", "event_ids": [4946]},
    {"rule_id": "evasion-007", "rule": "Firewall Rule Modified",
     "category": "Defense Evasion", "mitre": "T1562.004",
     "sigma_severity": "medium", "event_ids": [4947]},
    {"rule_id": "evasion-008", "rule": "Firewall Rule Deleted",
     "category": "Defense Evasion", "mitre": "T1562.004",
     "sigma_severity": "high", "event_ids": [4948]},
    {"rule_id": "evasion-009", "rule": "Windows Firewall Service Stopped",
     "category": "Defense Evasion", "mitre": "T1562.004",
     "sigma_severity": "critical", "event_ids": [5025]},
    {"rule_id": "evasion-010", "rule": "Windows Firewall Failed to Start",
     "category": "Defense Evasion", "mitre": "T1562.004",
     "sigma_severity": "critical", "event_ids": [5030]},
    {"rule_id": "evasion-011", "rule": "Firewall Rule Not Applied",
     "category": "Defense Evasion", "mitre": "T1562.004",
     "sigma_severity": "critical", "event_ids": [4957]},
    {"rule_id": "evasion-012", "rule": "Firewall Policy Retrieval Failed",
     "category": "Defense Evasion", "mitre": "T1562.004",
     "sigma_severity": "high", "event_ids": [5027, 5028]},
    {"rule_id": "evasion-013", "rule": "Kerberos Policy Changed",
     "category": "Defense Evasion", "mitre": "T1558.001",
     "sigma_severity": "critical", "event_ids": [4713]},
    {"rule_id": "evasion-014", "rule": "Event Log Service Stopped",
     "category": "Defense Evasion", "mitre": "T1070.001",
     "sigma_severity": "critical", "event_ids": [6006]},
    {"rule_id": "evasion-015", "rule": "Unexpected System Shutdown",
     "category": "Defense Evasion", "mitre": "T1529",
     "sigma_severity": "high", "event_ids": [6008]},
    {"rule_id": "evasion-016", "rule": "Boot Configuration Data Loaded",
     "category": "Defense Evasion", "mitre": "T1542.003",
     "sigma_severity": "critical", "event_ids": [4826]},
    {"rule_id": "evasion-017", "rule": "Object Permissions Changed",
     "category": "Defense Evasion", "mitre": "T1222",
     "sigma_severity": "medium", "event_ids": [4670]},
    {"rule_id": "evasion-018", "rule": "Password Policy API Called",
     "category": "Defense Evasion", "mitre": "T1110.003",
     "sigma_severity": "medium", "event_ids": [4793]},
    {"rule_id": "evasion-019", "rule": "Audit Policy Changed Then Log Cleared",
     "category": "Defense Evasion", "mitre": "T1562.002",
     "sigma_severity": "critical", "event_ids": [4719, 1102]},
    {"rule_id": "evasion-020", "rule": "Windows Defender Disabled via Audit Policy",
     "category": "Defense Evasion", "mitre": "T1562.001",
     "sigma_severity": "critical", "event_ids": [4719]},

    # Active Directory (DC-only)
    {"rule_id": "ad-001", "rule": "Active Directory Object Modified",
     "category": "Active Directory", "mitre": "T1484",
     "sigma_severity": "critical", "event_ids": [5136]},
    {"rule_id": "ad-002", "rule": "Active Directory Object Created",
     "category": "Active Directory", "mitre": "T1484",
     "sigma_severity": "high", "event_ids": [5137]},
    {"rule_id": "ad-003", "rule": "Active Directory Object Deleted",
     "category": "Active Directory", "mitre": "T1484",
     "sigma_severity": "high", "event_ids": [5141]},
    {"rule_id": "ad-004", "rule": "Active Directory Object Moved",
     "category": "Active Directory", "mitre": "T1484",
     "sigma_severity": "medium", "event_ids": [5139]},
    {"rule_id": "ad-005", "rule": "Active Directory Object Undeleted",
     "category": "Active Directory", "mitre": "T1484",
     "sigma_severity": "medium", "event_ids": [5138]},
]


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_all_detections(
    events: list[dict],
    brute_force_threshold: int = BRUTE_FORCE_THRESHOLD,
    brute_force_window: int = BRUTE_FORCE_WINDOW_MINUTES,
    spray_threshold: int = SPRAY_THRESHOLD,
    spray_window: int = SPRAY_WINDOW_MINUTES,
    lateral_threshold: int = LATERAL_THRESHOLD,
    lateral_window: int = LATERAL_WINDOW_MINUTES,
) -> list[dict]:
    """Run all detection rules against a normalised event list.

    Args:
        events: Sorted list of normalised event dicts from parser.parse().
        brute_force_threshold: Failed logon count to trigger brute force.
        brute_force_window: Time window in minutes for brute force detection.
        spray_threshold: Distinct account count to trigger password spraying.
        spray_window: Time window in minutes for spraying detection.
        lateral_threshold: Distinct target count to trigger lateral movement.
        lateral_window: Time window in minutes for lateral movement detection.

    Returns:
        Deduplicated list of alert dicts.
    """
    if not events:
        return []

    _log_audit_caveats(events)

    kwargs = {
        "brute_force_threshold": brute_force_threshold,
        "brute_force_window": brute_force_window,
        "spray_threshold": spray_threshold,
        "spray_window": spray_window,
        "lateral_threshold": lateral_threshold,
        "lateral_window": lateral_window,
    }

    alerts: list[dict] = []

    # Index events by ID for O(1) lookup
    by_id: dict[int, list[dict]] = defaultdict(list)
    for event in events:
        by_id[event["event_id"]].append(event)

    alerts += _detect_brute_force(by_id, **kwargs)
    alerts += _detect_password_spray(by_id, **kwargs)
    alerts += _detect_explicit_credential(by_id)
    alerts += _detect_off_hours_logon(by_id)
    alerts += _detect_rdp_logon(by_id)
    alerts += _detect_rdp_reconnect_anomaly(by_id)
    alerts += _detect_account_lockout(by_id)
    alerts += _detect_single_event_rules(by_id)
    alerts += _detect_multi_id_rules(by_id)
    alerts += _detect_group_changes(by_id)
    alerts += _detect_privilege_escalation_sequence(by_id)
    alerts += _detect_lateral_movement_sequence(by_id, **kwargs)
    alerts += _detect_pass_the_ticket(by_id)
    alerts += _detect_suspicious_process(by_id)
    alerts += _detect_suspicious_cmdline(by_id)
    alerts += _detect_short_lived_process(by_id)
    alerts += _detect_registry_process_sequence(by_id)
    alerts += _detect_firewall_change_burst(by_id)
    alerts += _detect_scheduled_task(by_id)
    alerts += _detect_service_account_interactive(by_id)
    alerts += _detect_mass_lockout(by_id)
    alerts += _detect_account_enumeration(by_id)
    alerts += _detect_registry_autorun(by_id)
    alerts += _detect_suspicious_service_install(by_id)
    alerts += _detect_sensitive_file_access(by_id)
    alerts += _detect_sensitive_permission_change(by_id)
    alerts += _detect_kerberoasting_rc4(by_id)
    alerts += _detect_runas_netonly(by_id)
    alerts += _detect_lateral_explicit_network(by_id)
    alerts += _detect_evasion_sequence(by_id)
    alerts += _detect_defender_disabled(by_id)
    alerts += _detect_ntlm_relay(by_id)

    return _deduplicate(alerts)


# ---------------------------------------------------------------------------
# Single-event rules (one alert per matching event)
# ---------------------------------------------------------------------------

_SINGLE_EVENT_RULE_MAP: dict[int, str] = {
    4648:  "logon-003",
    4649:  "replay-001",
    4964:  "special-001",
    4720:  "acct-001",
    4722:  "acct-002",
    4725:  "acct-003",
    4726:  "acct-004",
    4738:  "acct-005",
    4767:  "acct-007",
    4781:  "acct-008",
    4794:  "acct-010",
    4765:  "group-004",
    4766:  "group-005",
    4780:  "group-006",
    4798:  "recon-001",
    4799:  "recon-002",
    4672:  "priv-001",
    4673:  "priv-002",
    4674:  "priv-003",
    4703:  "priv-005",
    4704:  "priv-006",
    4705:  "priv-007",
    4699:  "persist-003",
    4700:  "persist-004",
    4657:  "persist-006",
    4706:  "persist-007",
    6416:  "persist-008",
    4886:  "persist-009",
    4887:  "persist-010",
    5861:  "persist-012",   # WMI subscription
    4610:  "persist-013",   # SSP loaded
    4771:  "lateral-002",
    4776:  "lateral-004",
    5140:  "lateral-005",
    5145:  "lateral-006",
    4104:  "exec-004",
    1102:  "evasion-001",
    4719:  "evasion-002",
    4906:  "evasion-003",
    4616:  "evasion-004",
    4716:  "evasion-005",
    4946:  "evasion-006",
    4947:  "evasion-007",
    4948:  "evasion-008",
    5025:  "evasion-009",
    5030:  "evasion-010",
    4957:  "evasion-011",
    4713:  "evasion-013",
    6006:  "evasion-014",
    6008:  "evasion-015",
    4826:  "evasion-016",
    4793:  "evasion-018",
    5136:  "ad-001",
    5137:  "ad-002",
    5141:  "ad-003",
    5139:  "ad-004",
    5138:  "ad-005",
    4778:  "logon-005",
    4779:  "logon-006",
    4740:  "lockout-001",
}


def _detect_single_event_rules(by_id: dict[int, list[dict]]) -> list[dict]:
    """Fire one alert per event for all single-event rules."""
    alerts = []
    rule_map = {r["rule_id"]: r for r in RULES}

    for event_id, rule_id in _SINGLE_EVENT_RULE_MAP.items():
        for event in by_id.get(event_id, []):
            rule = rule_map[rule_id]
            alerts.append(_make_alert(
                rule=rule,
                events=[event],
                computer=event["computer"],
                user=event["user"],
                ip=event.get("ip_address"),
                count=1,
                detail=_event_detail(event),
            ))
    return alerts


def _detect_multi_id_rules(by_id: dict) -> list[dict]:
    """Handle rules that match on multiple event IDs (OR logic)."""
    alerts = []
    multi_rules = [
        ([4723, 4724], "acct-009"),
        ([4697, 7045], "persist-005"),
        ([5027, 5028], "evasion-012"),
    ]
    rule_map = {r["rule_id"]: r for r in RULES}
    for event_ids, rule_id in multi_rules:
        rule = rule_map[rule_id]
        for eid in event_ids:
            for event in by_id.get(eid, []):
                alerts.append(_make_alert(
                    rule=rule, events=[event],
                    computer=event["computer"],
                    user=event["user"],
                    ip=event.get("ip_address"),
                    count=1,
                    detail=_event_detail(event),
                ))
    return alerts


# ---------------------------------------------------------------------------
# Multi-event / threshold rules
# ---------------------------------------------------------------------------

def _detect_brute_force(by_id: dict, brute_force_threshold: int,
                        brute_force_window: int, **_) -> list[dict]:
    """brute-001: ≥N failed logons from same source within window."""
    rule = _rule("brute-001")
    alerts = []
    events_4625 = by_id.get(4625, [])

    # Group by source IP, then check threshold in sliding window
    by_ip: dict[str, list[dict]] = defaultdict(list)
    for e in events_4625:
        key = e.get("ip_address") or e.get("user") or "unknown"
        by_ip[key].append(e)

    window = timedelta(minutes=brute_force_window)
    for source, evts in by_ip.items():
        evts_sorted = sorted(evts, key=lambda x: x["timestamp"])
        clusters = _sliding_window_clusters(evts_sorted, window,
                                            brute_force_threshold)
        for cluster in clusters:
            alerts.append(_make_alert(
                rule=rule,
                events=cluster,
                computer=cluster[0]["computer"],
                user=cluster[0].get("user"),
                ip=source if _is_ip(source) else None,
                count=len(cluster),
                detail=f"{len(cluster)} failed logons from {source} "
                       f"in {brute_force_window} min",
            ))
    return alerts


def _detect_password_spray(by_id: dict, spray_threshold: int,
                           spray_window: int, **_) -> list[dict]:
    """brute-002: failed logons targeting ≥N distinct accounts from same IP."""
    rule = _rule("brute-002")
    alerts = []
    events_4625 = by_id.get(4625, [])

    by_ip: dict[str, list[dict]] = defaultdict(list)
    for e in events_4625:
        ip = e.get("ip_address")
        if ip:
            by_ip[ip].append(e)

    window = timedelta(minutes=spray_window)
    for ip, evts in by_ip.items():
        evts_sorted = sorted(evts, key=lambda x: x["timestamp"])
        clusters = _sliding_window_clusters(evts_sorted, window, spray_threshold)
        for cluster in clusters:
            distinct_users = {e.get("user") for e in cluster if e.get("user")}
            if len(distinct_users) >= spray_threshold:
                alerts.append(_make_alert(
                    rule=rule,
                    events=cluster,
                    computer=cluster[0]["computer"],
                    user=None,
                    ip=ip,
                    count=len(cluster),
                    detail=f"Password spray from {ip} targeting "
                           f"{len(distinct_users)} accounts: "
                           f"{', '.join(sorted(distinct_users)[:5])}",
                ))
    return alerts


def _detect_explicit_credential(by_id: dict) -> list[dict]:
    """logon-003: 4648 explicit credential use."""
    return _detect_single_event_rules(
        {4648: by_id.get(4648, [])}
    )


def _detect_off_hours_logon(by_id: dict) -> list[dict]:
    """logon-004: successful logon outside business hours."""
    rule = _rule("logon-004")
    alerts = []
    for event in by_id.get(4624, []):
        ts = event["timestamp"]
        if (ts.weekday() not in BUSINESS_DAYS
                or ts.hour < BUSINESS_HOURS_START
                or ts.hour >= BUSINESS_HOURS_END):
            alerts.append(_make_alert(
                rule=rule,
                events=[event],
                computer=event["computer"],
                user=event["user"],
                ip=event.get("ip_address"),
                count=1,
                detail=f"Logon at {ts.strftime('%H:%M')} "
                       f"on {ts.strftime('%A')} (outside business hours)",
            ))
    return alerts


def _detect_rdp_logon(by_id: dict) -> list[dict]:
    """logon-002: 4624 with logon type 10 (RemoteInteractive = RDP)."""
    rule = _rule("logon-002")
    alerts = []
    for event in by_id.get(4624, []):
        if event.get("logon_type") == 10:
            alerts.append(_make_alert(
                rule=rule,
                events=[event],
                computer=event["computer"],
                user=event["user"],
                ip=event.get("ip_address"),
                count=1,
                detail=f"RDP logon from {event.get('ip_address', 'unknown')}",
            ))
    return alerts


def _detect_rdp_reconnect_anomaly(by_id: dict) -> list[dict]:
    """logon-005: ≥N RDP session reconnects within window."""
    rule = _rule("logon-005")
    alerts = []
    events_4778 = by_id.get(4778, [])
    if len(events_4778) < RDP_RECONNECT_THRESHOLD:
        return alerts

    window = timedelta(minutes=RDP_RECONNECT_WINDOW_MINUTES)
    by_user: dict[str, list[dict]] = defaultdict(list)
    for e in events_4778:
        key = e.get("user") or "unknown"
        by_user[key].append(e)

    for user, evts in by_user.items():
        evts_sorted = sorted(evts, key=lambda x: x["timestamp"])
        clusters = _sliding_window_clusters(
            evts_sorted, window, RDP_RECONNECT_THRESHOLD)
        for cluster in clusters:
            alerts.append(_make_alert(
                rule=rule,
                events=cluster,
                computer=cluster[0]["computer"],
                user=user,
                ip=None,
                count=len(cluster),
                detail=f"{len(cluster)} RDP reconnects for {user} "
                       f"in {RDP_RECONNECT_WINDOW_MINUTES} min",
            ))
    return alerts


def _detect_account_lockout(by_id: dict) -> list[dict]:
    """lockout-001 / acct-006: 4740 account lockout."""
    rule = _rule("lockout-001")
    return [
        _make_alert(
            rule=rule,
            events=[e],
            computer=e["computer"],
            user=e["user"],
            ip=e.get("ip_address"),
            count=1,
            detail=f"Account locked out: {e.get('user', 'unknown')}",
        )
        for e in by_id.get(4740, [])
    ]


def _detect_group_changes(by_id: dict) -> list[dict]:
    """group-001/002: member added/removed from privileged group."""
    alerts = []
    add_rule = _rule("group-001")
    remove_rule = _rule("group-002")
    change_rule = _rule("group-003")

    add_ids = {4732, 4728, 4756}
    remove_ids = {4733, 4729, 4757}
    change_ids = {4735, 4737, 4755}

    for eid in add_ids:
        for event in by_id.get(eid, []):
            group = _extract_group(event)
            if _is_privileged_group(group):
                alerts.append(_make_alert(
                    rule=add_rule,
                    events=[event],
                    computer=event["computer"],
                    user=event["user"],
                    ip=None,
                    count=1,
                    detail=f"Member added to privileged group: {group}",
                ))

    for eid in remove_ids:
        for event in by_id.get(eid, []):
            group = _extract_group(event)
            if _is_privileged_group(group):
                alerts.append(_make_alert(
                    rule=remove_rule,
                    events=[event],
                    computer=event["computer"],
                    user=event["user"],
                    ip=None,
                    count=1,
                    detail=f"Member removed from privileged group: {group}",
                ))

    for eid in change_ids:
        for event in by_id.get(eid, []):
            group = _extract_group(event)
            if _is_privileged_group(group):
                alerts.append(_make_alert(
                    rule=change_rule,
                    events=[event],
                    computer=event["computer"],
                    user=event["user"],
                    ip=None,
                    count=1,
                    detail=f"Privileged group changed: {group}",
                ))

    return alerts


def _detect_privilege_escalation_sequence(by_id: dict) -> list[dict]:
    """priv-004: 4624 followed by 4672 from same user within 30 seconds."""
    rule = _rule("priv-004")
    alerts = []
    window = timedelta(seconds=30)

    logons = sorted(by_id.get(4624, []), key=lambda e: e["timestamp"])
    privs = sorted(by_id.get(4672, []), key=lambda e: e["timestamp"])

    for logon in logons:
        user = logon.get("user")
        if not user:
            continue
        ts = logon["timestamp"]
        matching_privs = [
            p for p in privs
            if p.get("user") == user
            and ts <= p["timestamp"] <= ts + window
        ]
        if matching_privs:
            alerts.append(_make_alert(
                rule=rule,
                events=[logon] + matching_privs[:1],
                computer=logon["computer"],
                user=user,
                ip=logon.get("ip_address"),
                count=2,
                detail=f"Privilege escalation: {user} gained special "
                       f"privileges within {window.seconds}s of logon",
            ))
    return alerts


def _detect_lateral_movement_sequence(by_id: dict, lateral_threshold: int,
                                      lateral_window: int, **_) -> list[dict]:
    """lateral-001: network logons (type 3) to ≥N distinct targets."""
    rule = _rule("lateral-001")
    alerts = []
    window = timedelta(minutes=lateral_window)

    network_logons = [
        e for e in by_id.get(4624, [])
        if e.get("logon_type") == 3
    ]

    by_source: dict[str, list[dict]] = defaultdict(list)
    for e in network_logons:
        key = e.get("ip_address") or e.get("user") or "unknown"
        by_source[key].append(e)

    for source, evts in by_source.items():
        evts_sorted = sorted(evts, key=lambda x: x["timestamp"])
        clusters = _sliding_window_clusters(evts_sorted, window, lateral_threshold)
        for cluster in clusters:
            targets = {e["computer"] for e in cluster}
            if len(targets) >= lateral_threshold:
                alerts.append(_make_alert(
                    rule=rule,
                    events=cluster,
                    computer=cluster[0]["computer"],
                    user=cluster[0].get("user"),
                    ip=source if _is_ip(source) else None,
                    count=len(cluster),
                    detail=f"Lateral movement from {source} to "
                           f"{len(targets)} targets: "
                           f"{', '.join(sorted(targets)[:5])}",
                ))
    return alerts


def _detect_pass_the_ticket(by_id: dict) -> list[dict]:
    """lateral-003: 4768 (TGT) followed by 4769 (service ticket) - same user."""
    rule = _rule("lateral-003")
    alerts = []
    window = timedelta(minutes=KERBEROS_WINDOW_MINUTES)

    tgt_requests = sorted(by_id.get(4768, []), key=lambda e: e["timestamp"])
    svc_tickets = sorted(by_id.get(4769, []), key=lambda e: e["timestamp"])

    for tgt in tgt_requests:
        user = tgt.get("user")
        if not user:
            continue
        ts = tgt["timestamp"]
        matching = [
            s for s in svc_tickets
            if s.get("user") == user
            and ts <= s["timestamp"] <= ts + window
        ]
        if matching:
            alerts.append(_make_alert(
                rule=rule,
                events=[tgt] + matching[:1],
                computer=tgt["computer"],
                user=user,
                ip=tgt.get("ip_address"),
                count=2,
                detail=f"Kerberos TGT + service ticket for {user} "
                       f"within {window.seconds // 60} min (Pass-the-Ticket)",
            ))
    return alerts


def _detect_suspicious_process(by_id: dict) -> list[dict]:
    """exec-001 / exec-006: suspicious parent-child or known malicious process."""
    alerts_001 = []
    alerts_006 = []
    rule_001 = _rule("exec-001")
    rule_006 = _rule("exec-006")

    for event in by_id.get(4688, []):
        process = event.get("process_name", "") or ""
        parent = event.get("raw", {}).get("ParentProcessName", "").lower()
        parent_base = Path(parent).name if parent else ""

        # exec-006: known malicious process name
        if any(mal in process for mal in SUSPICIOUS_PROCESSES):
            alerts_006.append(_make_alert(
                rule=rule_006,
                events=[event],
                computer=event["computer"],
                user=event["user"],
                ip=None,
                count=1,
                detail=f"Known malicious process: {process}",
            ))
            continue

        # exec-001: suspicious parent-child combination
        if parent_base:
            for suspicious_parent, suspicious_child in SUSPICIOUS_PARENT_CHILD:
                if (suspicious_parent in parent_base
                        and suspicious_child in process):
                    alerts_001.append(_make_alert(
                        rule=rule_001,
                        events=[event],
                        computer=event["computer"],
                        user=event["user"],
                        ip=None,
                        count=1,
                        detail=f"Suspicious parent-child: "
                               f"{parent_base} → {process}",
                    ))
                    break

    return alerts_001 + alerts_006


def _detect_suspicious_cmdline(by_id: dict) -> list[dict]:
    """exec-002: 4688 with suspicious command line keywords."""
    rule = _rule("exec-002")
    alerts = []

    for event in by_id.get(4688, []):
        cmdline = (event.get("raw", {}).get("CommandLine", "")
                   or event.get("message", "")).lower()
        if not cmdline:
            continue
        matched = [kw for kw in SUSPICIOUS_CMDLINE_KEYWORDS if kw in cmdline]
        if matched:
            alerts.append(_make_alert(
                rule=rule,
                events=[event],
                computer=event["computer"],
                user=event["user"],
                ip=None,
                count=1,
                detail=f"Suspicious cmdline keywords: {', '.join(matched[:3])}",
            ))
    return alerts


def _detect_short_lived_process(by_id: dict) -> list[dict]:
    """exec-003: process created (4688) and exited (4689) within threshold."""
    rule = _rule("exec-003")
    alerts = []
    window = timedelta(seconds=SHORT_PROCESS_SECONDS)

    creations = {
        e.get("raw", {}).get("NewProcessId", ""): e
        for e in by_id.get(4688, [])
        if e.get("raw", {}).get("NewProcessId")
    }
    exits = by_id.get(4689, [])

    for exit_event in exits:
        pid = exit_event.get("raw", {}).get("ProcessId", "")
        creation = creations.get(pid)
        if not creation:
            continue
        duration = exit_event["timestamp"] - creation["timestamp"]
        if timedelta(0) <= duration <= window:
            alerts.append(_make_alert(
                rule=rule,
                events=[creation, exit_event],
                computer=creation["computer"],
                user=creation["user"],
                ip=None,
                count=2,
                detail=f"Process {creation.get('process_name', pid)} "
                       f"lived {duration.seconds}s",
            ))
    return alerts


def _detect_registry_process_sequence(by_id: dict) -> list[dict]:
    """exec-005: registry modification (4657) followed by process creation (4688)."""
    rule = _rule("exec-005")
    alerts = []
    window = timedelta(seconds=30)

    reg_events = sorted(by_id.get(4657, []), key=lambda e: e["timestamp"])
    proc_events = sorted(by_id.get(4688, []), key=lambda e: e["timestamp"])

    for reg in reg_events:
        user = reg.get("user")
        ts = reg["timestamp"]
        matching = [
            p for p in proc_events
            if p.get("user") == user
            and ts <= p["timestamp"] <= ts + window
        ]
        if matching:
            alerts.append(_make_alert(
                rule=rule,
                events=[reg, matching[0]],
                computer=reg["computer"],
                user=user,
                ip=None,
                count=2,
                detail=f"Registry mod followed by process creation "
                       f"within {window.seconds}s",
            ))
    return alerts


def _detect_firewall_change_burst(by_id: dict) -> list[dict]:
    """evasion-006/007/008: ≥N firewall rule changes in short window."""
    rule = _rule("evasion-008")  # Use highest-severity rule for bursts
    alerts = []
    window = timedelta(minutes=FIREWALL_CHANGE_WINDOW_MINUTES)

    fw_events = []
    for eid in (4946, 4947, 4948):
        fw_events.extend(by_id.get(eid, []))

    if len(fw_events) < FIREWALL_CHANGE_THRESHOLD:
        return alerts

    fw_sorted = sorted(fw_events, key=lambda e: e["timestamp"])
    clusters = _sliding_window_clusters(
        fw_sorted, window, FIREWALL_CHANGE_THRESHOLD)

    for cluster in clusters:
        alerts.append(_make_alert(
            rule=rule,
            events=cluster,
            computer=cluster[0]["computer"],
            user=cluster[0].get("user"),
            ip=None,
            count=len(cluster),
            detail=f"{len(cluster)} firewall rule changes in "
                   f"{FIREWALL_CHANGE_WINDOW_MINUTES} min",
        ))
    return alerts


# ---------------------------------------------------------------------------
# Scheduled task combined rules
# ---------------------------------------------------------------------------

def _detect_scheduled_task(by_id: dict) -> list[dict]:
    """persist-001/002: scheduled task created or modified."""
    alerts = []
    for eid, rule_id in [(4698, "persist-001"), (4702, "persist-002")]:
        rule = _rule(rule_id)
        for event in by_id.get(eid, []):
            task = event.get("task_name") or _extract_field(event, "TaskName")
            alerts.append(_make_alert(
                rule=rule,
                events=[event],
                computer=event["computer"],
                user=event["user"],
                ip=None,
                count=1,
                detail=f"Scheduled task: {task or 'unknown'}",
            ))
    return alerts


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

def _detect_service_account_interactive(by_id: dict) -> list[dict]:
    """logon-007: service account logging on interactively (type 2 or 10)."""
    rule = _rule("logon-007")
    alerts = []
    for event in by_id.get(4624, []):
        if event.get("logon_type") not in (2, 10):
            continue
        user = (event.get("user") or "").lower()
        if not user:
            continue
        if any(user.startswith(p) or user.endswith(p.rstrip("_").rstrip("-"))
               for p in SERVICE_ACCOUNT_PATTERNS):
            alerts.append(_make_alert(
                rule=rule,
                events=[event],
                computer=event["computer"],
                user=event["user"],
                ip=event.get("ip_address"),
                count=1,
                detail=f"Service account interactive logon "
                       f"(type {event.get('logon_type')}): {event['user']}",
            ))
    return alerts


def _detect_mass_lockout(by_id: dict) -> list[dict]:
    """lockout-002: multiple distinct accounts locked out within window."""
    rule = _rule("lockout-002")
    alerts = []
    events_4740 = sorted(by_id.get(4740, []), key=lambda e: e["timestamp"])
    if len(events_4740) < 3:
        return alerts
    window = timedelta(minutes=SPRAY_WINDOW_MINUTES)
    clusters = _sliding_window_clusters(events_4740, window, 3)
    for cluster in clusters:
        distinct = {e.get("user") for e in cluster if e.get("user")}
        if len(distinct) >= 3:
            alerts.append(_make_alert(
                rule=rule,
                events=cluster,
                computer=cluster[0]["computer"],
                user=None,
                ip=None,
                count=len(cluster),
                detail=f"Mass lockout: {len(distinct)} accounts locked "
                       f"in {SPRAY_WINDOW_MINUTES} min: "
                       f"{', '.join(sorted(distinct)[:5])}",
            ))
    return alerts


def _detect_account_enumeration(by_id: dict) -> list[dict]:
    """recon-003: 4625 failures where SubStatus=0xC0000064 (account does not exist).

    Distinct from brute force - attacker is probing for valid usernames,
    not hammering a known account. Volume threshold: 5+ distinct non-existent
    accounts from one source within the spray window.
    """
    rule = _rule("recon-003")
    alerts = []
    window = timedelta(minutes=SPRAY_WINDOW_MINUTES)

    by_source: dict[str, list[dict]] = defaultdict(list)
    for event in by_id.get(4625, []):
        substatus = event.get("raw", {}).get("SubStatus", "")
        if substatus in ("0xC0000064", "%%2305"):   # account does not exist
            key = event.get("ip_address") or event.get("user") or "unknown"
            by_source[key].append(event)

    for source, evts in by_source.items():
        evts_sorted = sorted(evts, key=lambda e: e["timestamp"])
        clusters = _sliding_window_clusters(evts_sorted, window, 5)
        for cluster in clusters:
            distinct = {e.get("user") for e in cluster if e.get("user")}
            if len(distinct) >= 5:
                alerts.append(_make_alert(
                    rule=rule,
                    events=cluster,
                    computer=cluster[0]["computer"],
                    user=None,
                    ip=source if _is_ip(source) else None,
                    count=len(cluster),
                    detail=f"Account enumeration from {source}: "
                           f"{len(distinct)} non-existent accounts probed: "
                           f"{', '.join(sorted(distinct)[:5])}",
                ))
    return alerts


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------

def _detect_registry_autorun(by_id: dict) -> list[dict]:
    """persist-011: 4657 modifying Run/RunOnce autostart registry keys."""
    rule = _rule("persist-011")
    alerts = []

    for event in by_id.get(4657, []):
        obj_name = event.get("raw", {}).get("ObjectName", "").lower()
        if any(key in obj_name for key in SENSITIVE_REGISTRY_PATHS):
            alerts.append(_make_alert(
                rule=rule,
                events=[event],
                computer=event["computer"],
                user=event["user"],
                ip=None,
                count=1,
                detail=f"Autorun registry key modified: {obj_name[-80:]}",
            ))
    return alerts


def _detect_suspicious_service_install(by_id: dict) -> list[dict]:
    """persist-005 variant: service installed from suspicious path (temp/appdata/users)."""
    rule = _rule("persist-005")
    alerts = []
    suspicious_paths = ["\\temp\\", "\\appdata\\", "\\users\\", "\\programdata\\",
                        "\\downloads\\", "\\desktop\\"]
    for eid in (4697, 7045):
        for event in by_id.get(eid, []):
            image_path = event.get("raw", {}).get("ImagePath", "").lower()
            if image_path and any(p in image_path for p in suspicious_paths):
                alerts.append(_make_alert(
                    rule=rule,
                    events=[event],
                    computer=event["computer"],
                    user=event["user"],
                    ip=None,
                    count=1,
                    detail=f"Service installed from suspicious path: {image_path[:100]}",
                ))
    return alerts


# ---------------------------------------------------------------------------
# Lateral movement
# ---------------------------------------------------------------------------

def _detect_kerberoasting_rc4(by_id: dict) -> list[dict]:
    """lateral-008: 4769 with RC4/DES encryption type = Kerberoasting."""
    rule = _rule("lateral-008")
    alerts = []
    for event in by_id.get(4769, []):
        etype = event.get("raw", {}).get("TicketEncryptionType", "")
        if etype in ("0x17", "0x18", "23", "24"):  # RC4 / DES
            alerts.append(_make_alert(
                rule=rule,
                events=[event],
                computer=event["computer"],
                user=event["user"],
                ip=event.get("ip_address"),
                count=1,
                detail=f"Kerberos service ticket with RC4 encryption "
                       f"(etype={etype}) — Kerberoasting indicator",
            ))
    return alerts


def _detect_runas_netonly(by_id: dict) -> list[dict]:
    """lateral-009: 4624 logon type 9 (NewCredentials) = runas /netonly."""
    rule = _rule("lateral-009")
    alerts = []
    for event in by_id.get(4624, []):
        if event.get("logon_type") == 9:
            alerts.append(_make_alert(
                rule=rule,
                events=[event],
                computer=event["computer"],
                user=event["user"],
                ip=event.get("ip_address"),
                count=1,
                detail=f"NewCredentials logon (runas /netonly) "
                       f"by {event.get('user', 'unknown')}",
            ))
    return alerts


def _detect_lateral_explicit_network(by_id: dict) -> list[dict]:
    """lateral-007: 4648 (explicit creds) followed by 4624 type 3 same user within 60s."""
    rule = _rule("lateral-007")
    alerts = []
    window = timedelta(seconds=60)

    explicit = sorted(by_id.get(4648, []), key=lambda e: e["timestamp"])
    network = sorted(
        [e for e in by_id.get(4624, []) if e.get("logon_type") == 3],
        key=lambda e: e["timestamp"],
    )

    for exp in explicit:
        user = exp.get("user")
        if not user:
            continue
        ts = exp["timestamp"]
        matching = [
            n for n in network
            if n.get("user") == user
            and ts <= n["timestamp"] <= ts + window
        ]
        if matching:
            alerts.append(_make_alert(
                rule=rule,
                events=[exp, matching[0]],
                computer=exp["computer"],
                user=user,
                ip=exp.get("ip_address"),
                count=2,
                detail=f"Explicit credential use followed by network logon "
                       f"within {window.seconds}s: {user}",
            ))
    return alerts


def _detect_ntlm_relay(by_id: dict) -> list[dict]:
    """lateral-010: 4624 type 3 with NTLM auth where IP doesn't match computer name."""
    rule = _rule("lateral-010")
    alerts = []
    for event in by_id.get(4624, []):
        if event.get("logon_type") != 3:
            continue
        auth_pkg = event.get("raw", {}).get("AuthenticationPackageName", "").upper()
        if "NTLM" not in auth_pkg:
            continue
        ip = event.get("ip_address", "")
        computer = event.get("computer", "").lower().split(".")[0]
        # Flag if source IP is present and doesn't resolve to the computer name
        if ip and _is_ip(ip) and not ip.startswith("127."):
            alerts.append(_make_alert(
                rule=rule,
                events=[event],
                computer=event["computer"],
                user=event["user"],
                ip=ip,
                count=1,
                detail=f"NTLM network logon from {ip} to {computer} "
                       f"— possible relay",
            ))
    return alerts


# ---------------------------------------------------------------------------
# Process & Execution
# ---------------------------------------------------------------------------

def _detect_sensitive_file_access(by_id: dict) -> list[dict]:
    """exec-007: 4663 file access on SAM, NTDS.dit, SYSTEM hive."""
    rule = _rule("exec-007")
    alerts = []
    for event in by_id.get(4663, []):
        obj_name = (event.get("raw", {}).get("ObjectName", "")
                    or event.get("message", "")).lower()
        if any(p in obj_name for p in SENSITIVE_FILE_PATHS):
            alerts.append(_make_alert(
                rule=rule,
                events=[event],
                computer=event["computer"],
                user=event["user"],
                ip=None,
                count=1,
                detail=f"Sensitive file accessed: {obj_name[-80:]}",
            ))
    return alerts


# ---------------------------------------------------------------------------
# Defense evasion
# ---------------------------------------------------------------------------

def _detect_evasion_sequence(by_id: dict) -> list[dict]:
    """evasion-019: audit policy changed (4719) then log cleared (1102) within 5 min."""
    rule = _rule("evasion-019")
    alerts = []
    window = timedelta(minutes=5)

    policy_changes = sorted(by_id.get(4719, []), key=lambda e: e["timestamp"])
    log_clears = sorted(by_id.get(1102, []), key=lambda e: e["timestamp"])

    for change in policy_changes:
        ts = change["timestamp"]
        matching = [
            c for c in log_clears
            if ts <= c["timestamp"] <= ts + window
        ]
        if matching:
            alerts.append(_make_alert(
                rule=rule,
                events=[change, matching[0]],
                computer=change["computer"],
                user=change.get("user"),
                ip=None,
                count=2,
                detail=f"Audit policy changed then log cleared "
                       f"within {window.seconds // 60} min",
            ))
    return alerts


def _detect_defender_disabled(by_id: dict) -> list[dict]:
    """evasion-020: 4719 where SubcategoryGuid matches MPSSVC (Defender policy)."""
    rule = _rule("evasion-020")
    alerts = []
    for event in by_id.get(4719, []):
        guid = event.get("raw", {}).get("SubcategoryGuid", "")
        if MPSSVC_SUBCATEGORY_GUID in guid:
            alerts.append(_make_alert(
                rule=rule,
                events=[event],
                computer=event["computer"],
                user=event["user"],
                ip=None,
                count=1,
                detail=f"Windows Defender audit policy disabled "
                       f"(SubcategoryGuid: {guid})",
            ))
    return alerts


def _detect_sensitive_permission_change(by_id: dict) -> list[dict]:
    """evasion-017: 4670 on sensitive objects (AD, SAM, LSASS, GPO)."""
    rule = _rule("evasion-017")
    alerts = []
    sensitive_objects = [
        "\\sam", "\\lsass", "ntds", "grouppolicy",
        "\\policies\\", "cn=domain", "defaultsecuritydescriptor",
    ]
    for event in by_id.get(4670, []):
        obj_name = (event.get("raw", {}).get("ObjectName", "")
                    or event.get("message", "")).lower()
        if any(s in obj_name for s in sensitive_objects):
            alerts.append(_make_alert(
                rule=rule,
                events=[event],
                computer=event["computer"],
                user=event["user"],
                ip=None,
                count=1,
                detail=f"Permissions changed on sensitive object: {obj_name[-80:]}",
            ))
    return alerts


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------

def _deduplicate(alerts: list[dict]) -> list[dict]:
    """Remove duplicate alerts by rule_id + computer + user + detail hash."""
    seen: set[tuple] = set()
    unique: list[dict] = []
    for alert in alerts:
        key = (alert["rule_id"], alert["computer"],
               alert.get("user"), alert["detail"])
        if key not in seen:
            seen.add(key)
            unique.append(alert)
    logger.info("Detected %d alert(s) after deduplication "
                "(%d raw)", len(unique), len(alerts))
    return unique


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _rule(rule_id: str) -> dict:
    """Lookup rule by ID."""
    for r in RULES:
        if r["rule_id"] == rule_id:
            return r
    raise KeyError(f"Unknown rule_id: {rule_id}")


def _make_alert(rule: dict, events: list[dict], computer: str,
                user: str | None, ip: str | None,
                count: int, detail: str) -> dict:
    """Build a standardised alert dict."""
    is_critical = any(
        e["event_id"] in CRITICAL_EVENT_IDS for e in events
    ) or rule["sigma_severity"] == "critical"

    return {
        "rule_id":        rule["rule_id"],
        "rule":           rule["rule"],
        "category":       rule["category"],
        "mitre":          rule["mitre"],
        "sigma_severity": "critical" if is_critical else rule["sigma_severity"],
        "event_ids":      rule["event_ids"],
        "computer":       computer or "unknown",
        "user":           user,
        "ip":             ip,
        "count":          count,
        "detail":         detail,
        "events":         events,
    }


def _sliding_window_clusters(events: list[dict], window: timedelta,
                             threshold: int) -> list[list[dict]]:
    """Find all clusters of ≥threshold events within a sliding time window."""
    clusters = []
    n = len(events)
    i = 0
    while i < n:
        j = i
        while j < n and events[j]["timestamp"] - events[i]["timestamp"] <= window:
            j += 1
        if j - i >= threshold:
            clusters.append(events[i:j])
        i += 1
    return clusters


def _event_detail(event: dict) -> str:
    """Build a short detail string from an event."""
    parts = []
    if event.get("user"):
        parts.append(f"user={event['user']}")
    if event.get("ip_address"):
        parts.append(f"ip={event['ip_address']}")
    if event.get("process_name"):
        parts.append(f"process={event['process_name']}")
    if event.get("task_name"):
        parts.append(f"task={event['task_name']}")
    if event.get("service_name"):
        parts.append(f"service={event['service_name']}")
    return ", ".join(parts) or event.get("message", "")[:100]


def _extract_group(event: dict) -> str:
    """Extract group name from event raw fields."""
    raw = event.get("raw", {})
    return (raw.get("TargetUserName")
            or raw.get("GroupName")
            or raw.get("MemberName")
            or "unknown").lower()


def _is_privileged_group(group_name: str) -> bool:
    """Return True if group name matches a known privileged group."""
    group_lower = group_name.lower()
    return any(pg in group_lower for pg in PRIVILEGED_GROUPS)


def _extract_field(event: dict, field: str) -> str | None:
    """Extract a field from event raw dict."""
    return event.get("raw", {}).get(field)


def _is_ip(value: str) -> bool:
    """Basic check if value looks like an IP address."""
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", value or ""))


def _log_audit_caveats(events: list[dict]) -> None:
    """Log informational messages when audit-dependent events are absent."""
    event_ids_present = {e["event_id"] for e in events}

    if not event_ids_present & REQUIRES_PROCESS_AUDITING:
        logger.info(
            "No process creation events (4688/4689) found. "
            "Enable 'Audit Process Creation' policy for exec-* rules."
        )
    if not event_ids_present & REQUIRES_POWERSHELL_LOGGING:
        logger.info(
            "No PowerShell ScriptBlock events (4104) found. "
            "Enable PowerShell ScriptBlock Logging for exec-004."
        )
    if not event_ids_present & REQUIRES_OBJECT_ACCESS_AUDITING:
        logger.info(
            "No object access events (4663/4670/5140) found. "
            "Enable 'Audit Object Access' policy for exec-007 and evasion-017."
        )
    dc_present = event_ids_present & DC_ONLY_EVENT_IDS
    if dc_present:
        logger.info("DC-only events present: %s", sorted(dc_present))
