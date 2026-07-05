# Changelog

All notable changes to this project are documented in this file.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [SemVer](https://semver.org/).
---

## [1.0.1] - 2026-07-05

### Changed
- Consolidated report output into a single `output/` directory. The unused
  `reports/` default (only reachable when constructing `ReportGenerator()`
  without arguments) has been removed; the default now points at `output/`,
  matching the CLI's `--output` default.

### Removed
- `DEFAULT_REPORT_DIR` from `config/settings.py` and the `reports/` directory.

---

## [1.0.0] - 2026-07-05

### Added
- **Incident correlation** (`src/correlator.py`): alerts sharing an actor
  entity (source IP, user) within a time window are grouped into scored
  incidents - console incident list, JSON `incidents` section and
  `GET /incidents` dashboard endpoint.
- **Sysmon / Defender / System channel rules** (13 new rules, total 107):
  LSASS access, remote thread injection, process tampering, startup-folder
  drops, suspicious-TLD DNS, C2-port connections, registry autorun (Sysmon);
  malware detected, real-time protection disabled, config tampering
  (Defender); security service disabled/crashed (System). All channel-gated
  to prevent event-ID collisions.
- **Sigma YAML rule loading** (`src/sigma_loader.py`, pyyaml dependency):
  runtime loading of "EventID + field filter" Sigma rules; three starter
  rules bundled in `rules/sigma/`; `--sigma-rules DIR` / `--no-sigma` flags;
  Sigma alerts scored by rule level.
- **Live capture**: `--live [--live-channel X --live-max N]` reads the local
  event log via wevtutil (Windows, elevated shell) - no export step.
- **Self-contained HTML report** (`--html`): severity tiles, category bars,
  incident cards with timeline, ranked alert table; light/dark, no external
  resources, all content HTML-escaped.
- `--min-severity LEVEL` CLI filter.
- Alert allowlist (`ALLOWLIST_IPS/USERS/COMPUTERS` in settings) with logged,
  auditable suppressions.
- Normalised event schema gained a `channel` field (all three parsers).
- GreyNoise keyless community mode: `GREYNOISE_COMMUNITY=true` enables
  unauthenticated lookups (10 IPs/day) per the official Community API docs;
  token remains optional for 50/week.

---

## [0.10.1] - 2026-07-04

### Fixed
- Process basenames were not extracted from Windows paths when running on
  Linux/macOS (POSIX `Path` does not split on backslashes) - parser and
  parent-child detection now use `PureWindowsPath`. Caught by the Linux CI
  matrix.

---

## [0.10.0] - 2026-07-04

### Added
- VirusTotal enricher: vendor verdict counts, reputation, AS owner per
  alert IP (`VIRUSTOTAL_TOKEN`).
- GreyNoise Community enricher: scanner/noise vs targeted-attack
  classification per alert IP (`GREYNOISE_TOKEN`).
- Curated attack-chain sample log (`data/sample_logs/sample_attack_chain.json`):
  spray → enumeration → service-account RDP → privilege escalation →
  encoded PowerShell → SAM access → triple persistence → Kerberoasting →
  backdoor admin → Defender-off → log clear, including Sysmon and Defender
  channel events.
- Coverage gate raised to 95% (289 tests, ~98% coverage).

### Changed
- `.gitignore` reorganised by category; curated `sample_*.json` logs are
  now tracked while raw exports stay ignored.

---

## [0.9.0] - 2026-07-04

### Added
- 94 SIGMA-style detection rules across 8 categories (Authentication,
  Account Management, Privilege Escalation, Persistence, Lateral Movement,
  Execution, Defense Evasion, Active Directory).
- JSONL parser with channel support for Security, Sysmon, Windows Defender
  and System logs.
- Enrichment pipeline: ipinfo.io geolocation/Tor, AbuseIPDB reputation,
  user/computer/process/privilege context classification.
- Flask REST API with upload analysis, severity/rule filtering and
  threshold overrides.
- Multi-file input with merged timeline for cross-file correlation.
- Test suite: 151 tests, ~91% coverage, CI matrix on Python 3.10–3.14.

### Fixed
- Sliding-window clustering emitted one alert per start offset; a single
  brute-force burst now produces exactly one alert.
- 4740 lockouts and 4778 RDP reconnects fired duplicate alerts through two
  detection paths.
- Service installs from suspicious paths fired `persist-005` twice.
- Service-account pattern matching flagged regular users ending in "sa"
  (e.g. `lisa`) as service accounts.
- NTLM relay rule flagged every NTLM network logon; now detects the
  relay-to-self pattern only.
- Unparseable timestamps were replaced with the current time, which could
  fabricate event clusters; such records are now skipped.
- IPv6 addresses were mangled by IPv4 port-stripping in the parser.
- Privileged group changes mapped to MITRE T1098.001 (cloud credentials);
  corrected to T1098.007 (Additional Local or Domain Groups).
- ipinfo.io token moved from URL query string to Authorization header.
---