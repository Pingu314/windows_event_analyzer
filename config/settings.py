"""
settings.py - Central configuration for Windows Event Analyzer

All tunable constants live here. Every module imports from this file.
No hardcoded values anywhere else.
"""

from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _pkg_version
from pathlib import Path

# ---------------------------------------------------------------------------
# Application metadata
# ---------------------------------------------------------------------------

try:
    APP_VERSION = _pkg_version("windows-event-analyzer")
except PackageNotFoundError:
    APP_VERSION = "dev"

# ---------------------------------------------------------------------------
# Detection thresholds
# ---------------------------------------------------------------------------

# Brute force: failed logon threshold and time window
BRUTE_FORCE_THRESHOLD = 5          # failed logons from one source
BRUTE_FORCE_WINDOW_MINUTES = 5

# Password spraying: multiple accounts from one source
SPRAY_THRESHOLD = 3                # distinct accounts targeted
SPRAY_WINDOW_MINUTES = 10

# Lateral movement: network logon sequence
LATERAL_THRESHOLD = 3              # distinct targets from one source
LATERAL_WINDOW_MINUTES = 15

# Short-lived process: created and exited within this window
SHORT_PROCESS_SECONDS = 10

# Off-hours logon window (24h). Compared against event timestamps, which
# parsers normalise to UTC - adjust these to your organisation's UTC offset.
BUSINESS_HOURS_START = 7           # 07:00
BUSINESS_HOURS_END = 19            # 19:00
BUSINESS_DAYS = [0, 1, 2, 3, 4]   # Monday–Friday (0=Monday)

# Kerberos ticket anomaly window
KERBEROS_WINDOW_MINUTES = 5

# RDP reconnect anomaly threshold
RDP_RECONNECT_THRESHOLD = 3
RDP_RECONNECT_WINDOW_MINUTES = 10

# Firewall rule changes threshold (multiple changes = suspicious)
FIREWALL_CHANGE_THRESHOLD = 3
FIREWALL_CHANGE_WINDOW_MINUTES = 5

# ---------------------------------------------------------------------------
# Severity tiers
# ---------------------------------------------------------------------------

# Risk score thresholds
SEVERITY_CRITICAL = 80
SEVERITY_HIGH = 50
SEVERITY_MEDIUM = 25
SEVERITY_LOW = 0

# CRITICAL events auto-escalate regardless of score
CRITICAL_EVENT_IDS = {
    1102,   # Audit log cleared
    4649,   # Replay attack detected
    4663,   # Sensitive file access (SAM/NTDS.dit) - only via exec-007 filter
    4713,   # Kerberos policy changed
    4765,   # SID History added
    4794,   # DSRM password set
    4826,   # Boot config data loaded
    4906,   # CrashOnAuditFail changed
    4957,   # Firewall rule not applied
    5025,   # Firewall service stopped
    5030,   # Firewall failed to start
    5136,   # AD object modified
    6006,   # Event log service stopped
    6008,   # Unexpected shutdown
}

# ---------------------------------------------------------------------------
# Risk scoring weights
# ---------------------------------------------------------------------------

WEIGHTS = {
    # Authentication
    "failed_logon":                  3,   # per event, capped
    "brute_force":                   25,
    "password_spray":                30,
    "explicit_credential":           20,
    "off_hours_logon":               15,
    "rdp_logon":                     10,
    "rdp_reconnect_anomaly":         15,
    "account_lockout":               20,
    "replay_attack":                 50,  # CRITICAL
    "special_groups_logon":          25,
    "service_account_logon":         35,
    "mass_lockout":                  30,

    # Account management
    "account_created":               20,
    "account_deleted":               25,
    "account_changed":               15,
    "account_enabled":               10,
    "account_disabled":              10,
    "account_unlocked":              10,
    "account_renamed":               25,
    "password_change":               10,
    "dsrm_password_set":             50,  # CRITICAL
    "group_member_added":            20,
    "group_member_removed":          10,
    "group_changed":                 20,
    "sid_history_added":             50,  # CRITICAL
    "sid_history_failed":            30,
    "shadow_admin_acl":              30,
    "group_recon":                   15,
    "account_enumeration":           25,

    # Privilege escalation
    "special_privilege_logon":       20,
    "privileged_service":            10,
    "privileged_object_access":      10,
    "privilege_escalation_sequence": 35,
    "token_right_adjusted":          25,
    "user_right_assigned":           20,
    "user_right_removed":            15,

    # Persistence
    "scheduled_task_created":        25,
    "scheduled_task_modified":       25,
    "scheduled_task_deleted":        15,
    "scheduled_task_enabled":        15,
    "service_installed":             25,
    "registry_modified":             15,
    "domain_trust_created":          30,
    "external_device":               15,
    "cert_request":                  15,
    "cert_approved":                 20,
    "registry_autorun":              30,
    "wmi_subscription":              35,
    "ssp_loaded":                    35,

    # Lateral movement
    "lateral_movement_sequence":     30,
    "kerberos_preauth_failure":      20,
    "pass_the_ticket":               40,
    "ntlm_auth":                     10,
    "smb_share_access":              15,
    "smb_share_enumeration":         20,
    "explicit_credential_network":   35,
    "kerberoasting_rc4":             40,
    "runas_netonly":                 20,
    "ntlm_relay":                    40,

    # Process execution
    "suspicious_process":            25,
    "suspicious_cmdline":            30,
    "short_lived_process":           15,
    "powershell_scriptblock":        25,
    "registry_process_sequence":     30,
    "sensitive_file_access":         50,  # CRITICAL

    # Defense evasion
    "audit_log_cleared":             50,  # CRITICAL
    "audit_log_clear_sequence":      50,  # CRITICAL
    "audit_policy_changed":          30,
    "crash_on_audit_fail":           50,  # CRITICAL
    "system_time_changed":           25,
    "trusted_domain_modified":       30,
    "firewall_rule_added":           15,
    "firewall_rule_modified":        15,
    "firewall_rule_deleted":         25,
    "firewall_stopped":              50,  # CRITICAL
    "firewall_start_failed":         50,  # CRITICAL
    "firewall_rule_not_applied":     35,
    "firewall_policy_failed":        25,
    "kerberos_policy_changed":       50,  # CRITICAL
    "password_policy_api":           15,
    "defender_disabled":             50,  # CRITICAL

    # Active Directory
    "ad_object_modified":            40,  # CRITICAL
    "ad_object_created":             30,
    "ad_object_deleted":             35,
    "ad_object_moved":               20,
    "ad_object_undeleted":           20,

    # ACL / permissions
    "permissions_changed":           20,

    # System
    "event_log_stopped":             50,  # CRITICAL
    "unexpected_shutdown":           35,
    "boot_config_loaded":            40,  # CRITICAL
}

# Maximum score (capped)
MAX_SCORE = 100

# ---------------------------------------------------------------------------
# Suspicious process indicators
# ---------------------------------------------------------------------------

SUSPICIOUS_PARENT_CHILD = [
    ("winword.exe",     "cmd.exe"),
    ("winword.exe",     "powershell.exe"),
    ("services.exe",    "cmd.exe"),
    ("services.exe",    "powershell.exe"),
    ("excel.exe",       "cmd.exe"),
    ("excel.exe",       "powershell.exe"),
    ("outlook.exe",     "cmd.exe"),
    ("outlook.exe",     "powershell.exe"),
    ("mshta.exe",       "powershell.exe"),
    ("wscript.exe",     "cmd.exe"),
    ("cscript.exe",     "cmd.exe"),
    ("rundll32.exe",    "powershell.exe"),
    ("regsvr32.exe",    "powershell.exe"),
    ("svchost.exe",     "cmd.exe"),
    ("lsass.exe",       "cmd.exe"),
    ("conhost.exe",     "powershell.exe"),
    ("conhost.exe",     "cmd.exe"),
    ("werfault.exe",    "cmd.exe"),
    ("mmc.exe",         "powershell.exe"),
    ("mmc.exe",         "cmd.exe"),
    ("cmd.exe",         "svchost.exe"),
    ("powershell.exe",  "svchost.exe"),
    ("wscript.exe",     "svchost.exe"),
    ("cscript.exe",     "svchost.exe"),
    ("mshta.exe",       "svchost.exe"),
]

SUSPICIOUS_CMDLINE_KEYWORDS = [
    "invoke-expression",
    "iex(",
    "encodedcommand",
    "-enc ",
    "downloadstring",
    "downloadfile",
    "invoke-webrequest",
    "bitsadmin",
    "certutil -decode",
    "certutil -urlcache",
    "net user /add",
    "net localgroup administrators",
    "reg add",
    "schtasks /create",
    "sc create",
    "wmic process call create",
    "bypass",
    "-noprofile",
    "-noninteractive",
    "hidden",
    "frombase64string",
    "system.reflection",
    "virtualalloc",
    "writeprocessmemory",
    "whoami /all",
    "net group",
    "dsquery",
    "-windowstyle hidden",
    "start-process",
    "invoke-mimikatz",
    "sharphound",
    "bloodhound",
    "add-mppreference",          # Windows Defender exclusion
    "set-mppreference",          # Windows Defender disable
    "disablerealtimemonitoring",
    "vssadmin delete shadows",   # ransomware indicator
    "wbadmin delete catalog",    # ransomware indicator
    "bcdedit /set",              # boot config tamper
    "fsutil usn deletejournal",  # anti-forensics
    "stratum+tcp",
    "stratum+ssl",
    "-o pool.",
    "--donate-level",
    "xmrig",
    "--cuda",
    "--opencl",
]

SUSPICIOUS_PROCESSES = [
    "mimikatz.exe",
    "pwdump.exe",
    "fgdump.exe",
    "wce.exe",
    "gsecdump.exe",
    "procdump.exe",
    "psexec.exe",
    "psexesvc.exe",
    "nc.exe",
    "ncat.exe",
    "netcat.exe",
    "cobalt",
    "beacon.exe",
    "meterpreter",
    "rubeus.exe",
    "sharpup.exe",
    "seatbelt.exe",
    "winpeas.exe",
    "lazagne.exe",
    "crackmapexec",
    "impacket",
    "cobaltstrike",
    "xmrig.exe",
    "minergate.exe",
    "cpuminer.exe",
    "ethminer.exe",
    "nbminer.exe",
    "phoenixminer.exe",
    "t-rex.exe",
    "gminer.exe",
    "lolminer.exe",
]

# ---------------------------------------------------------------------------
# Privileged groups to monitor for membership changes
# ---------------------------------------------------------------------------

PRIVILEGED_GROUPS = [
    "administrators",
    "domain admins",
    "enterprise admins",
    "schema admins",
    "group policy creator owners",
    "account operators",
    "backup operators",
    "print operators",
    "server operators",
    "network configuration operators",
    "remote desktop users",
    "distributed com users",
]

# ---------------------------------------------------------------------------
# DC-only event IDs
# (gracefully skipped if not present in log)
# ---------------------------------------------------------------------------

DC_ONLY_EVENT_IDS = {
    4768,   # Kerberos TGT request
    4769,   # Kerberos service ticket request
    4771,   # Kerberos pre-auth failure
    4776,   # NTLM credential validation
    4713,   # Kerberos policy changed
    4765,   # SID History added
    4766,   # SID History add failed
    4794,   # DSRM password set
    5136,   # AD object modified
    5137,   # AD object created
    5138,   # AD object undeleted
    5139,   # AD object moved
    5141,   # AD object deleted
}

# ---------------------------------------------------------------------------
# Audit-policy-dependent event IDs
# (require specific audit policy settings to be enabled)
# ---------------------------------------------------------------------------

REQUIRES_PROCESS_AUDITING = {
    4688,   # Process creation
    4689,   # Process exit
    4696,   # Primary token assigned
}

REQUIRES_POWERSHELL_LOGGING = {
    4104,   # PowerShell ScriptBlock logging
}

REQUIRES_OBJECT_ACCESS_AUDITING = {
    4656,   # Handle to object requested
    4658,   # Handle closed
    4660,   # Object deleted
    4663,   # Object access attempt
    4670,   # Permissions changed
    5140,   # Network share accessed
    5145,   # Network share check
}

# ---------------------------------------------------------------------------
# CSV export column mapping
# (Windows Event Viewer CSV column names vary by locale/version)
# ---------------------------------------------------------------------------

CSV_COLUMN_ALIASES = {
    "event_id":     ["Event ID", "EventID", "Id", "event_id"],
    "timestamp":    ["Date and Time", "TimeCreated", "Timestamp", "timestamp",
                     "Date/Time"],
    "source":       ["Source", "ProviderName", "source"],
    "computer":     ["Computer", "ComputerName", "computer"],
    "user":         ["User", "SubjectUserName", "TargetUserName", "user"],
    "level":        ["Level", "LevelDisplayName", "level"],
    "message":      ["Message", "Description", "message"],
    "logon_type":   ["Logon Type", "LogonType", "logon_type"],
    "ip_address":   ["Source Network Address", "IpAddress", "ip_address"],
    "process_name": ["New Process Name", "ProcessName", "process_name"],
    "task_name":    ["Task Name", "TaskName", "task_name"],
    "service_name": ["Service Name", "ServiceName", "service_name"],
}

# ---------------------------------------------------------------------------
# JSON export field mapping
# (field name variations across dataset formats)
# ---------------------------------------------------------------------------

JSON_FIELD_ALIASES = {
    "event_id":    ["EventID", "EventId", "event_id"],
    "timestamp":   ["EventTime", "@timestamp", "TimeCreated", "timestamp"],
    "source":      ["SourceName", "Provider", "source"],
    "computer":    ["Hostname", "Computer", "ComputerName", "computer"],
    "user":        ["SubjectUserName", "TargetUserName", "AccountName", "user"],
    "ip_address":  ["IpAddress", "SourceAddress", "SourceIp", "ip_address"],
    "logon_type":  ["LogonType", "logon_type"],
    "process_name": ["NewProcessName", "Image", "ProcessName", "process_name"],
    "channel":     ["Channel", "channel"],
}

# ---------------------------------------------------------------------------
# External service configuration
# ---------------------------------------------------------------------------

IPINFO_BASE_URL = "https://ipinfo.io"
IPINFO_REQUEST_TIMEOUT = 5  # seconds

# ---------------------------------------------------------------------------
# File handling
# ---------------------------------------------------------------------------

SUPPORTED_LOG_EXTENSIONS = {".evtx", ".csv", ".json"}
DEFAULT_REPORT_DIR = Path("reports")
DEFAULT_OUTPUT_DIR = Path("output")
REPORT_CSV_FIELDNAMES = [
    "rule_id", "rule", "category", "mitre", "sigma_severity",
    "severity", "score", "computer", "user", "ip", "count",
    "detail", "mitre_tags", "intel_country", "intel_org",
    "intel_is_tor", "user_context", "computer_context",
]

# ---------------------------------------------------------------------------
# Logon type mapping
# ---------------------------------------------------------------------------

LOGON_TYPES = {
    2:  "Interactive",
    3:  "Network",
    4:  "Batch",
    5:  "Service",
    7:  "Unlock",
    8:  "NetworkCleartext",
    9:  "NewCredentials",
    10: "RemoteInteractive",
    11: "CachedInteractive",
    12: "CachedRemoteInteractive",
    13: "CachedUnlock",
}

# ---------------------------------------------------------------------------
# Enricher configuration
# ---------------------------------------------------------------------------

SERVICE_ACCOUNT_PATTERNS = ["svc_", "svc-", "_svc", "sa_", "sa-", "adm_", "adm-"]
MACHINE_ACCOUNT_SUFFIX = "$"
HIGH_RISK_USERNAMES = ["administrator", "admin", "root", "guest", "krbtgt"]
DC_NAMING_PREFIXES = ["dc", "dc-", "dc_", "domaincontroller"]
SERVER_NAMING_PREFIXES = ["srv", "srv-", "server", "fs", "app", "db", "sql"]
WORKSTATION_NAMING_PREFIXES = ["ws", "ws-", "pc", "desktop", "laptop", "wks"]
HIGH_VALUE_ASSETS: list[str] = []
HIGH_RISK_COUNTRIES = ["CN", "RU", "KP", "IR", "NG", "UA", "RO", "BR"]
ABUSEIPDB_BASE_URL = "https://api.abuseipdb.com/api/v2"
ABUSEIPDB_REQUEST_TIMEOUT = 5

# ---------------------------------------------------------------------------
# Process enrichment
# ---------------------------------------------------------------------------

LOLBINS = [
    "certutil.exe", "mshta.exe", "wscript.exe", "cscript.exe",
    "regsvr32.exe", "rundll32.exe", "msiexec.exe", "installutil.exe",
    "regasm.exe", "regsvcs.exe", "msbuild.exe", "cmstp.exe",
    "wmic.exe", "schtasks.exe", "odbcconf.exe", "hh.exe",
    "esentutl.exe", "expand.exe", "findstr.exe", "makecab.exe",
    "mavinject.exe", "msdeploy.exe", "msdt.exe", "nltest.exe",
    "pcalua.exe", "replace.exe", "rpcping.exe",
]

SYSTEM_PROCESS_PATHS = [
    "c:\\windows\\system32\\",
    "c:\\windows\\syswow64\\",
    "c:\\windows\\",
]

# ---------------------------------------------------------------------------
# Privilege enrichment
# ---------------------------------------------------------------------------

SENSITIVE_PRIVILEGES = [
    "SeDebugPrivilege",
    "SeImpersonatePrivilege",
    "SeTcbPrivilege",
    "SeAssignPrimaryTokenPrivilege",
    "SeLoadDriverPrivilege",
    "SeBackupPrivilege",
    "SeRestorePrivilege",
    "SeTakeOwnershipPrivilege",
    "SeCreateTokenPrivilege",
    "SeSecurityPrivilege",
]

# ---------------------------------------------------------------------------
# Channel support
# ---------------------------------------------------------------------------

# Accepted log channels in JSONL parser
# Security is always included. Add Sysmon/Defender when those channels
# are present in your dataset.
SUPPORTED_CHANNELS = {
    "Security",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "System",
}

# Sysmon event IDs (Channel: Microsoft-Windows-Sysmon/Operational)
SYSMON_EVENT_IDS = {
    1,   # Process Create
    2,   # File creation time changed
    3,   # Network connection
    5,   # Process terminated
    7,   # Image loaded
    8,   # CreateRemoteThread
    10,  # ProcessAccess
    11,  # FileCreate
    12,  # RegistryEvent (object create/delete)
    13,  # RegistryEvent (value set)
    15,  # FileCreateStreamHash
    17,  # PipeEvent (created)
    18,  # PipeEvent (connected)
    22,  # DNSEvent
    23,  # FileDelete
    25,  # ProcessTampering
}

# Windows Defender event IDs (Channel: Microsoft-Windows-Windows Defender/Operational)
DEFENDER_EVENT_IDS = {
    1116,  # Malware detected
    1117,  # Action taken on malware
    1006,  # Scan result
    1008,  # Scan failed
    5001,  # Real-time protection disabled
    5004,  # Real-time protection configuration changed
    5007,  # Configuration changed
    5010,  # Scanning for malware disabled
    5012,  # Scanning for viruses disabled
}

# System log event IDs (Channel: System)
SYSTEM_EVENT_IDS = {
    7034,  # Service crashed unexpectedly
    7035,  # Service sent a start/stop control
    7036,  # Service entered running/stopped state
    7040,  # Service start type changed
    7045,  # New service installed (also in Security 4697)
}

# Sensitive file paths - access triggers exec-007
SENSITIVE_FILE_PATHS = [
    "\\sam",
    "\\ntds.dit",
    "\\system",
    "\\security",
    "\\lsass",
]

# Registry keys that indicate persistence or defence evasion when modified
SENSITIVE_REGISTRY_PATHS = [
    "currentversion\\run",
    "currentversion\\runonce",
    "currentversion\\runservices",
    "currentversion\\policies\\explorer\\run",
    "group policy\\scripts",
    "winlogon\\userinit",
    "winlogon\\shell",
    "currentcontrolset\\services",           # service binary path tampering
    "currentcontrolset\\control\\lsa",       # LSA protection bypass
    "currentcontrolset\\control\\securityproviders",  # SSP manipulation
    "currentcontrolset\\control\\print\\monitors",    # print monitor DLL hijack
]

# WMI subscription filter GUID for Defender audit policy (evasion-020)
# SubcategoryGuid for MPSSVC Rule-Level Policy Change
MPSSVC_SUBCATEGORY_GUID = "{0CCE9248-69AE-11D9-BED3-505054503030}"
