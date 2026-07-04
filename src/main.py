"""
main.py - Windows Event Analyzer CLI Entrypoint
SOC Portfolio Project | MITRE ATT&CK: Multiple techniques

Pipeline:
    parse → detect → score → enrich → map_mitre → report

Usage:
    evtx-analyze security.csv
    evtx-analyze C:\\logs\\
    evtx-analyze file1.csv file2.evtx C:\\logs\\ --recursive
    evtx-analyze --logs security.csv
    evtx-analyze --logs-dir C:\\logs\\ --recursive
"""
from __future__ import annotations

import argparse
import logging
import sys
from pathlib import Path

from config.settings import (
    BRUTE_FORCE_THRESHOLD,
    BRUTE_FORCE_WINDOW_MINUTES,
    DEFAULT_OUTPUT_DIR,
    LATERAL_THRESHOLD,
    LATERAL_WINDOW_MINUTES,
    LIVE_MAX_EVENTS,
    SIGMA_RULES_DIR,
    SPRAY_THRESHOLD,
    SPRAY_WINDOW_MINUTES,
)
from config.settings import SUPPORTED_LOG_EXTENSIONS as SUPPORTED_EXTENSIONS
from src.correlator import correlate
from src.detector import run_all_detections
from src.enricher import AlertContextEnricher
from src.mitre_mapper import map_many
from src.parser import parse, parse_live, parse_many
from src.report_generator import ReportGenerator
from src.risk_scorer import get_severity, score_all
from src.sigma_loader import load_sigma_rules

# Bundled Sigma rules live next to the package, not in the caller's cwd
_BUNDLED_SIGMA_DIR = Path(__file__).resolve().parent.parent / SIGMA_RULES_DIR

_SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


def analyze_events(
    events: list[dict],
    brute_force_threshold: int | None = None,
    brute_force_window: int | None = None,
    spray_threshold: int | None = None,
    spray_window: int | None = None,
    lateral_threshold: int | None = None,
    lateral_window: int | None = None,
    enricher: AlertContextEnricher | None = None,
    sigma_rules: list[dict] | None = None,
) -> list[dict]:
    """Detect → score → enrich → MITRE-map a normalised event list.

    Shared core used by file analysis (run_pipeline*), live capture
    (--live) and the dashboard.

    Args:
        events: Normalised event dicts from parser.parse()/parse_live().
        brute_force_threshold: Override default brute force threshold.
        brute_force_window: Override default brute force window (minutes).
        spray_threshold: Override default password spray threshold.
        spray_window: Override default spray window (minutes).
        lateral_threshold: Override default lateral movement threshold.
        lateral_window: Override default lateral movement window (minutes).
        enricher: Optional pre-instantiated AlertContextEnricher.
        sigma_rules: Optional converted Sigma rules (sigma_loader).

    Returns:
        List of enriched, scored, MITRE-tagged alert dicts.
    """
    kwargs = {
        "brute_force_threshold": brute_force_threshold or BRUTE_FORCE_THRESHOLD,
        "brute_force_window":    brute_force_window or BRUTE_FORCE_WINDOW_MINUTES,
        "spray_threshold":       spray_threshold or SPRAY_THRESHOLD,
        "spray_window":          spray_window or SPRAY_WINDOW_MINUTES,
        "lateral_threshold":     lateral_threshold or LATERAL_THRESHOLD,
        "lateral_window":        lateral_window or LATERAL_WINDOW_MINUTES,
    }

    alerts = run_all_detections(events, sigma_rules=sigma_rules, **kwargs)
    alerts = score_all(alerts)
    if enricher:
        alerts = enricher.enrich_alerts(alerts)
    alerts = map_many(alerts)
    logger.info("Detected %d alert(s).", len(alerts))
    return alerts


def run_pipeline(
    log_path: str | Path,
    enricher: AlertContextEnricher | None = None,
    sigma_rules: list[dict] | None = None,
    **threshold_overrides: int | None,
) -> list[dict]:
    """Run the full detection pipeline on a single log file.

    Args:
        log_path: Path to .evtx, .csv or .json file.
        enricher: Optional pre-instantiated AlertContextEnricher.
        sigma_rules: Optional converted Sigma rules.
        **threshold_overrides: See analyze_events().

    Returns:
        List of enriched, scored, MITRE-tagged alert dicts.
    """
    logger.info("Log file: %s", log_path)
    events = parse(str(log_path))
    logger.info("Parsed %d events.", len(events))
    return analyze_events(events, enricher=enricher,
                          sigma_rules=sigma_rules, **threshold_overrides)


def run_pipeline_multi(
    log_paths: list[str | Path],
    enricher: AlertContextEnricher | None = None,
    sigma_rules: list[dict] | None = None,
    **threshold_overrides: int | None,
) -> list[dict]:
    """Run the pipeline across multiple log files with merged event stream.

    All events are merged before detection - cross-file correlation applies.

    Args:
        log_paths: List of .evtx, .csv or .json paths.
        enricher: Optional pre-instantiated AlertContextEnricher.
        sigma_rules: Optional converted Sigma rules.
        **threshold_overrides: See analyze_events().

    Returns:
        List of enriched, scored, MITRE-tagged alert dicts.
    """
    events = parse_many([str(p) for p in log_paths])
    logger.info("Total: %d events across %d file(s).", len(events), len(log_paths))
    return analyze_events(events, enricher=enricher,
                          sigma_rules=sigma_rules, **threshold_overrides)


def collect_log_files(path: str | Path) -> list[Path]:
    """Collect supported log files (.evtx/.csv/.json) from a file or directory."""
    p = Path(path)
    if p.is_file():
        if p.suffix.lower() in SUPPORTED_EXTENSIONS:
            return [p]
        logger.warning("Unsupported file type: %s", p)
        return []
    if p.is_dir():
        files = sorted(
            f for f in p.iterdir()
            if f.is_file() and f.suffix.lower() in SUPPORTED_EXTENSIONS
        )
        logger.info("Found %d log file(s) in %s", len(files), p)
        return files
    logger.error("Path does not exist: %s", p)
    return []


def collect_log_files_recursive(path: str | Path) -> list[Path]:
    """Recursively collect supported log files (.evtx/.csv/.json) from a tree."""
    p = Path(path)
    if p.is_file():
        return collect_log_files(p)
    files = sorted(
        f for f in p.rglob("*")
        if f.is_file() and f.suffix.lower() in SUPPORTED_EXTENSIONS
    )
    logger.info("Found %d log file(s) recursively in %s", len(files), p)
    return files


def _resolve_inputs(args: argparse.Namespace) -> list[Path]:
    """Resolve all input sources to a deduplicated list of log file paths.

    Combines positional paths, --logs and --logs-dir.
    Each positional argument can be a file or directory.
    """
    all_files: list[Path] = []

    for raw_path in (args.paths or []):
        p = Path(raw_path)
        if p.is_dir():
            found = (collect_log_files_recursive(p) if args.recursive
                     else collect_log_files(p))
            all_files.extend(found)
        else:
            all_files.extend(collect_log_files(p))

    if args.logs:
        all_files.extend(collect_log_files(args.logs))

    if args.logs_dir:
        root = Path(args.logs_dir)
        found = (collect_log_files_recursive(root) if args.recursive
                 else collect_log_files(root))
        all_files.extend(found)

    # Deduplicate while preserving order
    seen: set[Path] = set()
    unique: list[Path] = []
    for f in all_files:
        if f not in seen:
            seen.add(f)
            unique.append(f)
    return unique


def _build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description=(
            "Windows Event Analyzer - detect attacks in Windows Security "
            "event logs (.evtx, .csv or .json)."
        ),
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        epilog="""
Examples:
  evtx-analyze security.csv
  evtx-analyze C:\\logs\\
  evtx-analyze file1.csv file2.evtx C:\\logs\\
  evtx-analyze C:\\logs\\ --recursive
  evtx-analyze security.csv --csv --brute-threshold 3
  evtx-analyze --logs security.csv
  evtx-analyze --logs-dir C:\\logs\\ --recursive
""",
    )

    p.add_argument(
        "paths",
        nargs="*",
        help="Files (.evtx/.csv/.json) or directories to analyze",
    )

    explicit = p.add_argument_group("explicit input flags")
    explicit.add_argument(
        "--logs", default=None,
        help="Path to a single .evtx, .csv or .json file",
    )
    explicit.add_argument(
        "--logs-dir", default=None,
        help="Directory - all .evtx/.csv/.json files will be processed",
    )

    p.add_argument(
        "--recursive", action="store_true",
        help="Recursively scan subdirectories",
    )
    p.add_argument(
        "--output", default=str(DEFAULT_OUTPUT_DIR),
        help="Directory for output files",
    )
    p.add_argument(
        "--no-export", action="store_true",
        help="Skip JSON and CSV export",
    )
    p.add_argument(
        "--csv", action="store_true",
        help="Also export CSV summary",
    )

    thresholds = p.add_argument_group("detection threshold overrides")
    thresholds.add_argument("--brute-threshold", type=int, default=None,
                            help="Brute force failed logon threshold")
    thresholds.add_argument("--brute-window", type=int, default=None,
                            help="Brute force time window (minutes)")
    thresholds.add_argument("--spray-threshold", type=int, default=None,
                            help="Password spray distinct account threshold")
    thresholds.add_argument("--spray-window", type=int, default=None,
                            help="Password spray time window (minutes)")
    thresholds.add_argument("--lateral-threshold", type=int, default=None,
                            help="Lateral movement distinct target threshold")
    thresholds.add_argument("--lateral-window", type=int, default=None,
                            help="Lateral movement time window (minutes)")

    live = p.add_argument_group("live capture (Windows, elevated shell)")
    live.add_argument("--live", action="store_true",
                      help="Read the local event log via wevtutil instead "
                           "of files")
    live.add_argument("--live-channel", default="Security",
                      help="Event log channel for --live")
    live.add_argument("--live-max", type=int, default=LIVE_MAX_EVENTS,
                      help="Newest N events to read with --live")

    p.add_argument(
        "--min-severity", default=None,
        choices=["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        type=str.upper,
        help="Drop alerts below this severity from output and exports",
    )
    p.add_argument(
        "--html", action="store_true",
        help="Also export a self-contained HTML report",
    )

    sigma = p.add_argument_group("Sigma rules")
    sigma.add_argument("--sigma-rules", default=None,
                       help="Directory or file with Sigma YAML rules "
                            "(default: bundled rules/sigma)")
    sigma.add_argument("--no-sigma", action="store_true",
                       help="Disable Sigma rule loading")
    return p


def _resolve_sigma_rules(args: argparse.Namespace) -> list[dict] | None:
    """Load Sigma rules per CLI flags (bundled rules by default)."""
    if args.no_sigma:
        return None
    if args.sigma_rules:
        return load_sigma_rules(args.sigma_rules)
    if _BUNDLED_SIGMA_DIR.is_dir():
        return load_sigma_rules(_BUNDLED_SIGMA_DIR)
    return None


def _filter_min_severity(alerts: list[dict], min_severity: str | None) -> list[dict]:
    """Drop alerts below the requested severity."""
    if not min_severity:
        return alerts
    floor = _SEVERITY_ORDER[min_severity]
    kept = [
        a for a in alerts
        if _SEVERITY_ORDER.get(
            a.get("risk", {}).get("severity")
            or get_severity(a.get("risk", {}).get("score", 0)), 1) >= floor
    ]
    logger.info("Severity filter %s: kept %d of %d alert(s)",
                min_severity, len(kept), len(alerts))
    return kept


def main() -> None:
    """CLI entrypoint for evtx-analyze."""
    args = _build_arg_parser().parse_args()

    override_kwargs: dict = {
        "brute_force_threshold": args.brute_threshold,
        "brute_force_window":    args.brute_window,
        "spray_threshold":       args.spray_threshold,
        "spray_window":          args.spray_window,
        "lateral_threshold":     args.lateral_threshold,
        "lateral_window":        args.lateral_window,
    }

    enricher = AlertContextEnricher()
    sigma_rules = _resolve_sigma_rules(args)

    if args.live:
        try:
            events = parse_live(channel=args.live_channel,
                                max_events=args.live_max)
        except RuntimeError as e:
            print(f"[!] Live capture failed: {e}")
            sys.exit(2)
        alerts = analyze_events(events, enricher=enricher,
                                sigma_rules=sigma_rules, **override_kwargs)
    else:
        all_files = _resolve_inputs(args)
        if not all_files:
            _build_arg_parser().print_help()
            sys.exit(1)

        if len(all_files) == 1:
            alerts = run_pipeline(
                all_files[0], enricher=enricher,
                sigma_rules=sigma_rules, **override_kwargs)
        else:
            logger.info(
                "Processing %d file(s) with cross-file correlation.",
                len(all_files))
            alerts = run_pipeline_multi(
                all_files, enricher=enricher,
                sigma_rules=sigma_rules, **override_kwargs)

    alerts = _filter_min_severity(alerts, args.min_severity)
    incidents = correlate(alerts)

    reporter = ReportGenerator(report_dir=args.output)
    reporter.print_summary(alerts, incidents=incidents)

    if not args.no_export and alerts:
        try:
            json_path = reporter.export(alerts, incidents=incidents)
            print(f"\n[+] JSON report: {json_path}")
        except OSError as e:
            print(f"[!] Could not write JSON report: {e}")

        if args.csv:
            try:
                csv_path = reporter.export_csv(alerts)
                print(f"[+] CSV report:  {csv_path}")
            except OSError as e:
                print(f"[!] Could not write CSV report: {e}")

        if args.html:
            try:
                html_path = reporter.export_html(alerts, incidents=incidents)
                print(f"[+] HTML report: {html_path}")
            except OSError as e:
                print(f"[!] Could not write HTML report: {e}")


if __name__ == "__main__":
    main()
