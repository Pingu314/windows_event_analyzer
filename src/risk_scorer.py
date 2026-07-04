"""
risk_scorer.py - Risk Scorer for Windows Event Analyzer

Produces a 0–100 risk score, severity label and breakdown for each alert.
CRITICAL events auto-escalate to score 100 regardless of weighted calculation.

Severity tiers (configurable in settings.py):
    CRITICAL  80–100
    HIGH      50–79
    MEDIUM    25–49
    LOW        0–24
"""
from __future__ import annotations

import logging

from config.settings import (
    CRITICAL_EVENT_IDS,
    MAX_SCORE,
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SIGMA_LEVEL_SCORES,
    WEIGHTS,
)

logger = logging.getLogger(__name__)

# Maps rule_id to the weight key(s) in settings.WEIGHTS
_RULE_WEIGHT_MAP: dict[str, list[str]] = {
    # Authentication
    "brute-001":   ["brute_force"],
    "brute-002":   ["password_spray"],
    "logon-001":   ["rdp_logon"],
    "logon-002":   ["rdp_logon"],
    "logon-003":   ["explicit_credential"],
    "logon-004":   ["off_hours_logon"],
    "logon-005":   ["rdp_reconnect_anomaly"],
    "logon-006":   ["rdp_logon"],
    "logon-007":   ["service_account_logon"],
    "lockout-001": ["account_lockout"],
    "lockout-002": ["mass_lockout"],
    "replay-001":  ["replay_attack"],
    "special-001": ["special_groups_logon"],

    # Account management
    "acct-001":    ["account_created"],
    "acct-002":    ["account_enabled"],
    "acct-003":    ["account_disabled"],
    "acct-004":    ["account_deleted"],
    "acct-005":    ["account_changed"],
    "acct-006":    ["account_lockout"],
    "acct-007":    ["account_unlocked"],
    "acct-008":    ["account_renamed"],
    "acct-009":    ["password_change"],
    "acct-010":    ["dsrm_password_set"],
    "group-001":   ["group_member_added"],
    "group-002":   ["group_member_removed"],
    "group-003":   ["group_changed"],
    "group-004":   ["sid_history_added"],
    "group-005":   ["sid_history_failed"],
    "group-006":   ["shadow_admin_acl"],
    "recon-001":   ["group_recon"],
    "recon-002":   ["group_recon"],
    "recon-003":   ["account_enumeration"],

    # Privilege escalation
    "priv-001":    ["special_privilege_logon"],
    "priv-002":    ["privileged_service"],
    "priv-003":    ["privileged_object_access"],
    "priv-004":    ["privilege_escalation_sequence"],
    "priv-005":    ["token_right_adjusted"],
    "priv-006":    ["user_right_assigned"],
    "priv-007":    ["user_right_removed"],

    # Persistence
    "persist-001": ["scheduled_task_created"],
    "persist-002": ["scheduled_task_modified"],
    "persist-003": ["scheduled_task_deleted"],
    "persist-004": ["scheduled_task_enabled"],
    "persist-005": ["service_installed"],
    "persist-006": ["registry_modified"],
    "persist-007": ["domain_trust_created"],
    "persist-008": ["external_device"],
    "persist-009": ["cert_request"],
    "persist-010": ["cert_approved"],
    "persist-011": ["registry_autorun"],
    "persist-012": ["wmi_subscription"],
    "persist-013": ["ssp_loaded"],

    # Lateral movement
    "lateral-001": ["lateral_movement_sequence"],
    "lateral-002": ["kerberos_preauth_failure"],
    "lateral-003": ["pass_the_ticket"],
    "lateral-004": ["ntlm_auth"],
    "lateral-005": ["smb_share_access"],
    "lateral-006": ["smb_share_enumeration"],
    "lateral-007": ["explicit_credential_network"],
    "lateral-008": ["kerberoasting_rc4"],
    "lateral-009": ["runas_netonly"],
    "lateral-010": ["ntlm_relay"],

    # Execution
    "exec-001":    ["suspicious_process"],
    "exec-002":    ["suspicious_cmdline"],
    "exec-003":    ["short_lived_process"],
    "exec-004":    ["powershell_scriptblock"],
    "exec-005":    ["registry_process_sequence"],
    "exec-006":    ["suspicious_process"],
    "exec-007":    ["sensitive_file_access"],

    # Defense evasion
    "evasion-001": ["audit_log_cleared"],
    "evasion-002": ["audit_policy_changed"],
    "evasion-003": ["crash_on_audit_fail"],
    "evasion-004": ["system_time_changed"],
    "evasion-005": ["trusted_domain_modified"],
    "evasion-006": ["firewall_rule_added"],
    "evasion-007": ["firewall_rule_modified"],
    "evasion-008": ["firewall_rule_deleted"],
    "evasion-009": ["firewall_stopped"],
    "evasion-010": ["firewall_start_failed"],
    "evasion-011": ["firewall_rule_not_applied"],
    "evasion-012": ["firewall_policy_failed"],
    "evasion-013": ["kerberos_policy_changed"],
    "evasion-014": ["event_log_stopped"],
    "evasion-015": ["unexpected_shutdown"],
    "evasion-016": ["boot_config_loaded"],
    "evasion-017": ["permissions_changed"],
    "evasion-018": ["password_policy_api"],
    "evasion-019": ["audit_log_clear_sequence"],
    "evasion-020": ["defender_disabled"],

    # Active Directory
    "ad-001":      ["ad_object_modified"],
    "ad-002":      ["ad_object_created"],
    "ad-003":      ["ad_object_deleted"],
    "ad-004":      ["ad_object_moved"],
    "ad-005":      ["ad_object_undeleted"],

    # Sysmon channel
    "sysmon-001":  ["sysmon_suspicious_cmdline"],
    "sysmon-002":  ["remote_thread_created"],
    "sysmon-003":  ["lsass_access"],
    "sysmon-004":  ["sysmon_registry_autorun"],
    "sysmon-005":  ["dns_suspicious_tld"],
    "sysmon-006":  ["process_tampering"],
    "sysmon-007":  ["startup_folder_file"],
    "sysmon-008":  ["suspicious_net_connection"],

    # Windows Defender channel
    "defender-001": ["defender_malware_detected"],
    "defender-002": ["defender_rtp_disabled"],
    "defender-003": ["defender_config_tampered"],

    # System channel
    "system-001":  ["security_service_disabled"],
    "system-002":  ["security_service_crashed"],
}


def score(alert: dict) -> dict:
    """Calculate risk score, severity and breakdown for a single alert.

    CRITICAL events (settings.CRITICAL_EVENT_IDS) and rules with
    sigma_severity='critical' auto-escalate to score 100.

    Args:
        alert: Alert dict from detector.run_all_detections().

    Returns:
        Dict with keys: score (int), severity (str), breakdown (dict).
    """
    rule_id = alert.get("rule_id", "")
    sigma_severity = alert.get("sigma_severity", "")
    event_ids = alert.get("event_ids", [])
    count = alert.get("count", 1)

    # CRITICAL auto-escalation
    is_critical = (
        sigma_severity == "critical"
        or any(eid in CRITICAL_EVENT_IDS for eid in event_ids)
    )
    if is_critical:
        return {
            "score":     100,
            "severity":  "CRITICAL",
            "breakdown": {"critical_auto_escalation": 100},
        }

    breakdown: dict[str, int] = {}
    total = 0

    weight_keys = _RULE_WEIGHT_MAP.get(rule_id, [])
    for key in weight_keys:
        pts = WEIGHTS.get(key, 0)
        if pts:
            breakdown[key] = pts
            total += pts

    # Runtime-loaded Sigma rules have no weight entry - score by their level
    if not weight_keys and rule_id.startswith("sigma-"):
        pts = SIGMA_LEVEL_SCORES.get(sigma_severity, 25)
        breakdown["sigma_level"] = pts
        total += pts

    # Count bonus: each additional event beyond the first adds a small bonus
    if count > 1:
        count_bonus = min((count - 1) * WEIGHTS.get("failed_logon", 3), 20)
        breakdown["count_bonus"] = count_bonus
        total += count_bonus

    final_score = min(total, MAX_SCORE)
    severity = _severity_label(final_score)

    return {
        "score":     final_score,
        "severity":  severity,
        "breakdown": breakdown,
    }


def score_all(alerts: list[dict]) -> list[dict]:
    """Score a list of alerts, adding risk dict to each.

    Args:
        alerts: List of alert dicts from detector.run_all_detections().

    Returns:
        Same list with 'risk' key added to each alert.
    """
    for alert in alerts:
        alert["risk"] = score(alert)
    return alerts


def get_severity(risk_score: int) -> str:
    """Return severity label for a given risk score.

    Args:
        risk_score: Integer 0–100.

    Returns:
        One of: 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'
    """
    return _severity_label(risk_score)


def _severity_label(risk_score: int) -> str:
    if risk_score >= SEVERITY_CRITICAL:
        return "CRITICAL"
    if risk_score >= SEVERITY_HIGH:
        return "HIGH"
    if risk_score >= SEVERITY_MEDIUM:
        return "MEDIUM"
    return "LOW"
