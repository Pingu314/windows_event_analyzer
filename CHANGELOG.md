# Changelog

All notable changes to this project are documented in this file.
Format based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning follows [SemVer](https://semver.org/).
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