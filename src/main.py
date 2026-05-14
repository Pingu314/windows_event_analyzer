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
    SPRAY_THRESHOLD,
    SPRAY_WINDOW_MINUTES,
)
from config.settings import SUPPORTED_LOG_EXTENSIONS as SUPPORTED_EXTENSIONS
from src.detector import run_all_detections
from src.enricher import IPEnricher
from src.mitre_mapper import map_many
from src.parser import parse, parse_many
from src.report_generator import ReportGenerator
from src.risk_scorer import score_all

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


def run_pipeline(
    log_path: str | Path,
    brute_force_threshold: int | None = None,
    brute_force_window: int | None = None,
    spray_threshold: int | None = None,
    spray_window: int | None = None,
    lateral_threshold: int | None = None,
    lateral_window: int | None = None,
    enricher: IPEnricher | None = None,
) -> list[dict]:
    """Run the full detection pipeline on a single log file.

    Args:
        log_path: Path to .evtx or .csv file.
        brute_force_threshold: Override default brute force threshold.
        brute_force_window: Override default brute force window (minutes).
        spray_threshold: Override default password spray threshold.
        spray_window: Override default spray window (minutes).
        lateral_threshold: Override default lateral movement threshold.
        lateral_window: Override default lateral movement window (minutes).
        enricher: Optional pre-instantiated IPEnricher (reused across batch).

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

    logger.info("Log file: %s", log_path)
    events = parse(str(log_path))
    logger.info("Parsed %d events.", len(events))

    alerts = run_all_detections(events, **kwargs)
    alerts = score_all(alerts)
    if enricher:
        alerts = enricher.enrich_alerts(alerts)
    alerts = map_many(alerts)
    logger.info("Detected %d alert(s).", len(alerts))
    return alerts


def run_pipeline_multi(
    log_paths: list[str | Path],
    brute_force_threshold: int | None = None,
    brute_force_window: int | None = None,
    spray_threshold: int | None = None,
    spray_window: int | None = None,
    lateral_threshold: int | None = None,
    lateral_window: int | None = None,
    enricher: IPEnricher | None = None,
) -> list[dict]:
    """Run the pipeline across multiple log files with merged event stream.

    All events are merged before detection - cross-file correlation applies.

    Args:
        log_paths: List of .evtx or .csv paths.
        enricher: Optional pre-instantiated IPEnricher.
        (other args same as run_pipeline)

    Returns:
        List of enriched, scored, MITRE-tagged alert dicts.
    """

    resolved = {
        "brute_force_threshold": brute_force_threshold or BRUTE_FORCE_THRESHOLD,
        "brute_force_window":    brute_force_window or BRUTE_FORCE_WINDOW_MINUTES,
        "spray_threshold":       spray_threshold or SPRAY_THRESHOLD,
        "spray_window":          spray_window or SPRAY_WINDOW_MINUTES,
        "lateral_threshold":     lateral_threshold or LATERAL_THRESHOLD,
        "lateral_window":        lateral_window or LATERAL_WINDOW_MINUTES,
    }

    events = parse_many([str(p) for p in log_paths])
    logger.info("Total: %d events across %d file(s).", len(events), len(log_paths))

    alerts = run_all_detections(events, **resolved)
    alerts = score_all(alerts)
    if enricher:
        alerts = enricher.enrich_alerts(alerts)
    alerts = map_many(alerts)
    logger.info("Detected %d alert(s).", len(alerts))
    return alerts


def collect_log_files(path: str | Path) -> list[Path]:
    """Collect .evtx and .csv files from a file path or directory."""
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
    """Recursively collect .evtx and .csv files from a directory tree."""
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
            "event logs (.evtx or .csv)."
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
        help="Files (.evtx/.csv) or directories to analyze",
    )

    explicit = p.add_argument_group("explicit input flags")
    explicit.add_argument(
        "--logs", default=None,
        help="Path to a single .evtx or .csv file",
    )
    explicit.add_argument(
        "--logs-dir", default=None,
        help="Directory — all .evtx/.csv files will be processed",
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
    return p


def main() -> None:
    """CLI entrypoint for evtx-analyze."""
    args = _build_arg_parser().parse_args()

    all_files = _resolve_inputs(args)

    if not all_files:
        _build_arg_parser().print_help()
        sys.exit(1)

    override_kwargs: dict = {
        "brute_force_threshold": args.brute_threshold,
        "brute_force_window":    args.brute_window,
        "spray_threshold":       args.spray_threshold,
        "spray_window":          args.spray_window,
        "lateral_threshold":     args.lateral_threshold,
        "lateral_window":        args.lateral_window,
    }

    enricher = IPEnricher()

    if len(all_files) == 1:
        alerts = run_pipeline(
            all_files[0], enricher=enricher, **override_kwargs)
    else:
        logger.info(
            "Processing %d file(s) with cross-file correlation.", len(all_files))
        alerts = run_pipeline_multi(
            all_files, enricher=enricher, **override_kwargs)

    reporter = ReportGenerator(report_dir=args.output)
    reporter.print_summary(alerts)

    if not args.no_export and alerts:
        try:
            json_path = reporter.export(alerts)
            print(f"\n[+] JSON report: {json_path}")
        except OSError as e:
            print(f"[!] Could not write JSON report: {e}")

        if args.csv:
            try:
                csv_path = reporter.export_csv(alerts)
                print(f"[+] CSV report:  {csv_path}")
            except OSError as e:
                print(f"[!] Could not write CSV report: {e}")


if __name__ == "__main__":
    main()
