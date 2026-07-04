"""
mitre_mapper.py - MITRE ATT&CK tag mapper for Windows Event Analyzer

Maps alert rule IDs and features to MITRE ATT&CK technique strings.
Accepts the alert dict produced by detector.run_all_detections().
"""
from __future__ import annotations

# Full technique descriptions keyed by technique ID
_TECHNIQUE_NAMES: dict[str, str] = {
    "T1003":     "T1003 - OS Credential Dumping",
    "T1003.001": "T1003.001 - LSASS Memory",
    "T1003.002": "T1003.002 - Security Account Manager",
    "T1021":     "T1021 - Remote Services",
    "T1021.001": "T1021.001 - Remote Desktop Protocol",
    "T1021.002": "T1021.002 - SMB/Windows Admin Shares",
    "T1027":     "T1027 - Obfuscated Files or Information",
    "T1052.001": "T1052.001 - Exfiltration over USB",
    "T1053.005": "T1053.005 - Scheduled Task",
    "T1055":     "T1055 - Process Injection",
    "T1055.012": "T1055.012 - Process Hollowing",
    "T1059":     "T1059 - Command and Scripting Interpreter",
    "T1059.001": "T1059.001 - PowerShell",
    "T1059.003": "T1059.003 - Windows Command Shell",
    "T1068":     "T1068 - Exploitation for Privilege Escalation",
    "T1069.001": "T1069.001 - Local Groups Discovery",
    "T1070.001": "T1070.001 - Clear Windows Event Logs",
    "T1070.006": "T1070.006 - Timestomp",
    "T1071":     "T1071 - Application Layer Protocol",
    "T1071.001": "T1071.001 - Web Protocols",
    "T1071.004": "T1071.004 - DNS",
    "T1078":     "T1078 - Valid Accounts",
    "T1078.001": "T1078.001 - Default Accounts",
    "T1078.002": "T1078.002 - Domain Accounts",
    "T1078.003": "T1078.003 - Local Accounts",
    "T1087.002": "T1087.002 - Domain Account Discovery",
    "T1098":     "T1098 - Account Manipulation",
    "T1098.007": "T1098.007 - Additional Local or Domain Groups",
    "T1105":     "T1105 - Ingress Tool Transfer",
    "T1110.001": "T1110.001 - Password Guessing",
    "T1110.003": "T1110.003 - Password Spraying",
    "T1112":     "T1112 - Modify Registry",
    "T1134":     "T1134 - Access Token Manipulation",
    "T1134.001": "T1134.001 - Token Impersonation/Theft",
    "T1134.005": "T1134.005 - SID-History Injection",
    "T1135":     "T1135 - Network Share Discovery",
    "T1136.001": "T1136.001 - Create Local Account",
    "T1190":     "T1190 - Exploit Public-Facing Application",
    "T1204":     "T1204 - User Execution",
    "T1204.002": "T1204.002 - Malicious File",
    "T1222":     "T1222 - File and Directory Permissions Modification",
    "T1484":     "T1484 - Domain Policy Modification",
    "T1484.002": "T1484.002 - Domain Trust Modification",
    "T1489":     "T1489 - Service Stop",
    "T1529":     "T1529 - System Shutdown/Reboot",
    "T1531":     "T1531 - Account Access Removal",
    "T1542.003": "T1542.003 - Bootkit",
    "T1543.003": "T1543.003 - Windows Service",
    "T1546.003": "T1546.003 - Windows Management Instrumentation Event Subscription",
    "T1547.001": "T1547.001 - Registry Run Keys / Startup Folder",
    "T1547.005": "T1547.005 - Security Support Provider",
    "T1550":     "T1550 - Use Alternate Authentication Material",
    "T1550.002": "T1550.002 - Pass the Hash",
    "T1550.003": "T1550.003 - Pass the Ticket",
    "T1553.004": "T1553.004 - Install Root Certificate",
    "T1557.001": "T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay",
    "T1558":     "T1558 - Steal or Forge Kerberos Tickets",
    "T1558.001": "T1558.001 - Golden Ticket",
    "T1558.003": "T1558.003 - Kerberoasting",
    "T1562.001": "T1562.001 - Disable or Modify Tools",
    "T1562.002": "T1562.002 - Disable Windows Event Logging",
    "T1562.004": "T1562.004 - Disable or Modify System Firewall",
    "T1566":     "T1566 - Phishing",
}


def map_to_mitre(alert: dict) -> list[str]:
    """Map an alert dict to a list of MITRE ATT&CK technique strings.

    The primary technique comes from the rule definition. Additional
    contextual techniques are added based on alert features.

    Args:
        alert: Alert dict produced by detector.run_all_detections().

    Returns:
        Deduplicated list of MITRE technique strings, e.g.
        ['T1110.001 - Password Guessing', 'T1078 - Valid Accounts']
    """
    tags: list[str] = []
    seen: set[str] = set()

    def add(technique_id: str) -> None:
        label = _TECHNIQUE_NAMES.get(technique_id, technique_id)
        if label not in seen:
            seen.add(label)
            tags.append(label)

    # Primary technique from rule definition
    primary = alert.get("mitre", "")
    if primary:
        add(primary)

    rule_id = alert.get("rule_id", "")
    detail = (alert.get("detail") or "").lower()
    event_ids = set(alert.get("event_ids", []))

    # Authentication rules - add contextual techniques
    if rule_id in ("brute-001", "lockout-001", "acct-006"):
        add("T1078")                    # failed logons indicate credential attacks

    if rule_id == "brute-002":
        add("T1078")

    if rule_id in ("logon-001", "logon-002", "lateral-001"):
        add("T1078")                    # valid accounts used for remote access

    if rule_id == "logon-003":
        add("T1078")                    # explicit credentials = valid account abuse

    # Privilege escalation sequences
    if rule_id == "priv-004":
        add("T1078")                    # valid account used before escalation

    if rule_id in ("priv-005", "priv-006"):
        add("T1068")                    # token manipulation often precedes exploitation

    # Lateral movement
    if rule_id == "lateral-003":
        add("T1550")                    # pass-the-ticket is alternate auth material

    if rule_id == "lateral-004":
        add("T1550.002")                # NTLM = potential pass-the-hash

    # Persistence
    if rule_id in ("persist-001", "persist-002"):
        add("T1078")                    # scheduled tasks often created by valid account

    if rule_id == "persist-005":
        add("T1543.003")
        add("T1078")

    if rule_id == "persist-007":
        add("T1484")                    # domain trust = domain policy modification

    # Defense evasion
    if rule_id in ("evasion-001", "evasion-014"):
        add("T1562.002")                # clearing logs also disables logging

    if rule_id == "evasion-003":
        add("T1070.001")                # CrashOnAuditFail disables audit logging

    if rule_id == "evasion-013":
        add("T1558.001")                # Kerberos policy change → Golden Ticket

    if rule_id in ("evasion-009", "evasion-010", "evasion-011"):
        add("T1562.002")                # firewall changes also impair defences

    # Active Directory
    if rule_id in ("ad-001", "ad-002", "ad-003"):
        add("T1484")                    # all AD object changes = policy modification

    if rule_id == "group-004":
        add("T1078")                    # SID injection gives valid account access

    # Account management
    if rule_id in ("acct-001", "acct-008"):
        add("T1078")                    # new/renamed accounts = valid account creation

    if rule_id == "acct-010":
        add("T1078.003")                # DSRM = local account backdoor on DC

    # Execution
    if rule_id == "exec-004":
        add("T1059")                    # PowerShell is a scripting interpreter

    if rule_id == "exec-005":
        add("T1059")                    # registry + process = script execution chain

    # New detection rules - contextual MITRE mapping
    if rule_id == "logon-007":
        add("T1078.002")                # service account = domain account abuse

    if rule_id == "lockout-002":
        add("T1110.003")                # mass lockout = password spray pattern

    if rule_id in ("persist-011",):
        add("T1112")                    # autorun key = registry modification

    if rule_id == "persist-012":
        add("T1546.003")                # WMI subscription

    if rule_id == "persist-013":
        add("T1547.005")                # SSP loaded

    if rule_id in ("lateral-007", "lateral-009", "lateral-010"):
        add("T1550")                    # alternate auth material

    if rule_id == "lateral-008":
        add("T1558")                    # Kerberos ticket manipulation

    if rule_id == "evasion-019":
        add("T1070.001")                # clearing logs

    if rule_id == "evasion-020":
        add("T1562.002")                # disabling audit/logging

    if rule_id == "exec-007":
        add("T1003")                    # credential dumping via file access

    if rule_id == "recon-003":
        add("T1078")                    # enumeration precedes valid account use

    # Detail-based contextual mapping
    if "kerberos" in detail or "ticket" in detail:
        add("T1558")
    if "rdp" in detail or "remote interactive" in detail:
        add("T1021.001")
    if "smb" in detail or "share" in detail:
        add("T1021.002")
    if "spray" in detail:
        add("T1110.003")
    if "lateral" in detail:
        add("T1021")
    if "cmdline" in detail or "powershell" in detail:
        add("T1059.001")
    if "registry" in detail:
        add("T1112")
    if "scheduled task" in detail:
        add("T1053.005")
    if "firewall" in detail:
        add("T1562.004")
    if "rc4" in detail or "kerberoast" in detail:
        add("T1558.003")
    if "ntlm relay" in detail:
        add("T1557.001")
    if "defender" in detail:
        add("T1562.001")
    if "autorun" in detail or "run key" in detail:
        add("T1547.001")
    if "wmi" in detail:
        add("T1546.003")
    if "sensitive file" in detail or "ntds" in detail or "\\sam" in detail:
        add("T1003")

    # Ingress tool transfer - downloads
    if "downloadstring" in detail or "downloadfile" in detail or "bitsadmin" in detail:
        add("T1105")

    # Obfuscation
    if "encodedcommand" in detail or "frombase64string" in detail or "-enc " in detail:
        add("T1027")

    # Windows command shell
    if "cmd.exe" in detail or "cmd /c" in detail:
        add("T1059.003")

    # Web protocols used for C2 / download
    if "invoke-webrequest" in detail or "downloadstring" in detail:
        add("T1071.001")
        add("T1071")

    # Event-ID-based mapping for multi-event rules
    if 4688 in event_ids and "exec" not in rule_id:
        add("T1059")
    if {4768, 4769} & event_ids:
        add("T1550.003")
    if {4698, 4702} & event_ids:
        add("T1053.005")
    if {4732, 4728, 4756} & event_ids:
        add("T1098.007")

    return tags


def map_many(alerts: list[dict]) -> list[dict]:
    """Add MITRE tags to a list of alerts in-place.

    Args:
        alerts: List of alert dicts from detector.run_all_detections().

    Returns:
        Same list with 'mitre_tags' key added to each alert.
    """
    for alert in alerts:
        alert["mitre_tags"] = map_to_mitre(alert)
    return alerts
