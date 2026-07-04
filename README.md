# Windows Event Analyzer

[![CI](https://github.com/Pingu314/windows_event_analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/Pingu314/windows_event_analyzer/actions/workflows/ci.yml)
![Coverage](https://img.shields.io/badge/coverage-97%25-brightgreen)
![Python](https://img.shields.io/badge/python-3.10%20%E2%80%93%203.14-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A detection and triage tool that hunts for attack patterns in Windows Security
event logs. It parses EVTX, CSV and JSONL exports, runs **94 SIGMA-style
detection rules** across 8 attack categories, scores every alert 0–100,
enriches it with threat intelligence and asset context, and maps it to
**MITRE ATT&CK** techniques - from raw log to prioritised triage report in
one command.

Same craft as fraud monitoring in the card business: ingest a stream of
events, separate signal from noise, cluster bursts into one case, score the
risk and triage what matters first. I spent two years doing exactly this kind
of triage in 24/7 fraud detection at a Swiss payment services provider - this
project rebuilds the craft on Windows logs. Part of a detection engineering
portfolio.

```
evtx-analyze security.evtx
```

## Sample output

```
============================================================
  TRIAGE SUMMARY - 19 alert(s)
============================================================
  CRITICAL : 2
  HIGH     : 1
  MEDIUM   : 9
  LOW      : 7

  By category:
    Authentication                 7
    Defense Evasion                4
    Account Management             2
    Privilege Escalation           2
    Lateral Movement               2
    Persistence                    2
============================================================

  CRITICAL / HIGH alerts:
  [HIGH    ] [brute-002   ] Password Spraying
             computer=ws01.corp.local user=None score=50
             Password spray from 185.220.101.1 targeting 4 accounts: admin, administrator, guest, svc_backup
             MITRE: T1110.003 - Password Spraying, T1078 - Valid Accounts

  [CRITICAL] [evasion-001 ] Audit Log Cleared
             computer=ws01.corp.local user=jsmith score=100
             MITRE: T1070.001 - Clear Windows Event Logs, T1562.002 - Disable Windows Event Logging

  [CRITICAL] [evasion-009 ] Windows Firewall Service Stopped
             computer=ws01.corp.local user=None score=100
             MITRE: T1562.004 - Disable or Modify System Firewall
```

## Quick start

```bash
git clone https://github.com/Pingu314/windows_event_analyzer.git
cd windows_event_analyzer
pip install -e .

# analyze the bundled sample logs
evtx-analyze data/sample_logs/security.csv
evtx-analyze data/sample_logs/sample_attack_chain.json   # full intrusion chain

# analyze your own logs - files, directories, mixed formats
evtx-analyze security.evtx
evtx-analyze C:\logs\ --recursive
evtx-analyze dc01.evtx fileserver.csv sentinel_export.json
```

Multiple inputs are merged into one timeline before detection, so
**cross-file correlation** works: a brute force that starts in one log and the
lateral movement it enables in another are both caught.

## Pipeline

```
 parse ──► detect ──► score ──► enrich ──► map MITRE ──► report
 (EVTX/     (94        (0-100,    (ipinfo,     (ATT&CK       (console,
  CSV/       rules)     CRITICAL   AbuseIPDB,   techniques)    JSON, CSV,
  JSONL)                auto-      user/host/                  REST API)
                        escalation) process ctx)
```

| Stage | Module | What it does |
|---|---|---|
| Parse | `src/parser.py` | Normalises EVTX, Event Viewer CSV and JSONL (Security, Sysmon, Defender, System channels) into one event schema. Handles locale date formats, UTF-8 BOM, field-name aliases. |
| Detect | `src/detector.py` | 94 rules: threshold rules (brute force, spray, mass lockout), sequence rules (logon→privilege, policy-change→log-clear), and single-event rules. Non-overlapping window clustering - one burst = one alert. |
| Score | `src/risk_scorer.py` | Weighted 0–100 risk score with severity tiers. Critical events (log cleared, DSRM password, SID history…) auto-escalate to 100. |
| Enrich | `src/enricher.py` | IP geolocation/Tor/ASN (ipinfo.io), IP reputation (AbuseIPDB), vendor verdicts (VirusTotal), scanner/noise classification (GreyNoise), account classification (service/machine/privileged), host classification (DC/server/workstation), LOLBin + path anomaly, sensitive privileges. All API enrichers degrade gracefully without tokens. |
| Map | `src/mitre_mapper.py` | Primary technique per rule plus contextual techniques from alert features. |
| Report | `src/report_generator.py`, `src/dashboard.py` | Console triage summary, timestamped JSON/CSV reports, Flask REST API. |

## Detection coverage

| Category | Rules | Examples |
|---|---|---|
| Defense Evasion | 20 | Audit log cleared, firewall tampering, Defender disabled, CrashOnAuditFail, time change |
| Account Management | 19 | Privileged group changes, SID history injection, DSRM password, account enumeration |
| Authentication | 13 | Brute force, password spraying, off-hours logon, RDP anomalies, mass lockout |
| Persistence | 13 | Scheduled tasks, service installs from user-writable paths, autorun keys, WMI subscriptions, SSP load |
| Lateral Movement | 10 | Pass-the-ticket, Kerberoasting (RC4 downgrade), NTLM relay-to-self, SMB enumeration |
| Privilege Escalation | 7 | Logon→special-privilege sequences, token/user-right manipulation |
| Execution | 7 | Suspicious parent-child (Office→shell), encoded PowerShell, LOLBins, SAM/NTDS access |
| Active Directory | 5 | AD object create/modify/delete/move (DC-only, auto-skipped elsewhere) |

Rules that depend on optional audit policies (process creation 4688,
PowerShell ScriptBlock 4104, object access 4663) activate automatically when
those events are present; a caveat is logged when they are not. DC-only events
never fire false alerts on member servers.

## REST API

```bash
python -m src.dashboard          # http://127.0.0.1:5000
```

| Endpoint | Description |
|---|---|
| `GET /alerts` | Cached alerts from sample data (`limit`/`offset` pagination) |
| `GET /alerts/summary` | Severity, category and top-rule breakdown |
| `GET /alerts/severity/<level>` | Filter by CRITICAL/HIGH/MEDIUM/LOW |
| `GET /alerts/<rule_id>` | Filter by rule, e.g. `brute-001` |
| `POST /analyze` | Upload one or more log files (multipart), returns alerts |
| `DELETE /cache` | Reset the sample-data cache |

```bash
curl -F "file=@security.csv" "http://127.0.0.1:5000/analyze?brute_threshold=3"
```

## Configuration

Every tunable lives in [`config/settings.py`](config/settings.py) - detection
thresholds, scoring weights, suspicious process/cmdline lists, privileged
groups, naming conventions, high-risk countries. No hardcoded values in the
pipeline modules.

Threat-intel enrichment is optional. Copy `.env.example` to `.env` and add
free-tier tokens:

```
IPINFO_TOKEN=...       # ipinfo.io  - 50k lookups/month free
ABUSEIPDB_TOKEN=...    # AbuseIPDB  - 1k checks/day free
VIRUSTOTAL_TOKEN=...   # VirusTotal - 500 lookups/day free
GREYNOISE_TOKEN=...    # GreyNoise  - free community tier
```

Each token unlocks one enricher; any subset works. GreyNoise is the SOC
noise-filter: it tells internet-wide scanner background noise apart from
targeted attacks against *your* network.

Thresholds can also be overridden per run:

```bash
evtx-analyze security.csv --brute-threshold 3 --brute-window 10 --spray-threshold 5
```

## Tuning & false positives

Detection is a trade-off between coverage and noise. Design choices made here:

- **One burst, one alert** - threshold rules use non-overlapping window
  clustering, so a 500-attempt brute force produces one alert with
  `count=500`, not hundreds of alerts.
- **Severity does the triage** - informational rules (RDP disconnects,
  privileged service calls) score LOW and stay out of the CRITICAL/HIGH
  console detail; they are still in the JSON export for hunting.
- **Context-gated rules** - group changes only alert on *privileged* groups;
  service installs only get escalated detail from user-writable paths; NTLM
  logons only alert on the relay-to-self pattern, not every NTLM auth.
- **Environment-specific lists** - service-account patterns, business hours,
  host naming conventions and the user watchlist in `settings.py` should be
  adapted to your environment before judging alert quality.

## Testing

```bash
pip install -e ".[dev]"
pytest            # 289 tests, coverage gate 95% (currently ~98%)
```

CI runs ruff + the test matrix on Python 3.10–3.14.

## Docker

```bash
docker build -t evtx-analyze .
docker run --rm -v C:\logs:/logs evtx-analyze /logs/security.csv
```

## Limitations

Honest scope notes - this is a triage/portfolio tool, not a SIEM:

- Batch analysis only; no live event ingestion or tailing.
- Business-hours logic compares against UTC timestamps; adjust
  `BUSINESS_HOURS_*` in settings to your organisation's UTC offset.
- Ambiguous CSV dates (`01/02/2024`) are parsed US-first (`%m/%d/%Y`).
- The Flask dashboard has no authentication or rate limiting - local use only.
- Detection rules are heuristics tuned for lab datasets; production use
  requires environment-specific tuning (see above).

## Portfolio context

| # | Project | Description |
|---|---------|-------------|
| P1 | [soc_threat_analyzer](https://github.com/Pingu314/soc_threat_analyzer) | Log-based threat detection - brute force, password spraying, impossible travel |
| P2 | [phishing_url_analyzer](https://github.com/Pingu314/phishing_url_analyzer) | Phishing URL analysis pipeline with threat-intel enrichment |
| P3 | [email_header_analyzer](https://github.com/Pingu314/email_header_analyzer) | Email header analysis - SPF/DKIM/DMARC, routing, MIME evasion |
| P4 | **windows_event_analyzer** | This project - Windows Security event log triage across 94 detection rules |

## License

MIT - see [LICENSE](LICENSE).