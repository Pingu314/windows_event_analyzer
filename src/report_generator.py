"""
report_generator.py - Report Generator for Windows Event Analyzer

Serialises enriched alerts to JSON and CSV.
"""
from __future__ import annotations

import csv
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from config.settings import DEFAULT_REPORT_DIR as _REPORT_DIR

logger = logging.getLogger(__name__)

_CSV_FIELDNAMES = [
    "rule_id",
    "rule",
    "category",
    "mitre",
    "sigma_severity",
    "severity",
    "score",
    "computer",
    "user",
    "ip",
    "count",
    "detail",
    "mitre_tags",
]


class ReportGenerator:
    """Generates JSON and CSV reports from enriched alert lists."""

    def __init__(self, report_dir: str | Path = _REPORT_DIR) -> None:
        self._dir = Path(report_dir)
        self._ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    def _ensure_dir(self) -> None:
        self._dir.mkdir(parents=True, exist_ok=True)

    def export(self, alerts: list[dict]) -> str:
        """Write alerts to a timestamped JSON file.

        Args:
            alerts: Enriched alert dicts (with 'risk' and 'mitre_tags' keys).

        Returns:
            Path to the written file as a string.
        """
        self._ensure_dir()
        path = self._dir / f"report_{self._ts}.json"

        # Serialise - strip non-serialisable 'events' list to avoid
        # dumping full event payloads into the report by default
        serialisable = [_prepare_for_json(a) for a in alerts]

        with open(path, "w", encoding="utf-8") as f:
            json.dump(serialisable, f, indent=2, default=str)

        logger.info("JSON report written: %s (%d alerts)", path, len(alerts))
        return str(path)

    def export_csv(self, alerts: list[dict]) -> str:
        """Write a flat summary CSV - one row per alert.

        Args:
            alerts: Enriched alert dicts (with 'risk' and 'mitre_tags' keys).

        Returns:
            Path to the written file as a string.
        """
        self._ensure_dir()
        path = self._dir / f"report_{self._ts}.csv"

        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=_CSV_FIELDNAMES,
                                    extrasaction="ignore")
            writer.writeheader()
            for alert in alerts:
                writer.writerow(_flatten_for_csv(alert))

        logger.info("CSV report written: %s (%d alerts)", path, len(alerts))
        return str(path)

    def print_summary(self, alerts: list[dict]) -> None:
        """Print a triage summary to stdout."""
        if not alerts:
            print("\nNo alerts detected.")
            return

        by_severity: dict[str, int] = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0
        }
        by_category: dict[str, int] = {}

        for alert in alerts:
            sev = alert.get("risk", {}).get("severity", "LOW")
            by_severity[sev] = by_severity.get(sev, 0) + 1
            cat = alert.get("category", "Unknown")
            by_category[cat] = by_category.get(cat, 0) + 1

        print(f"\n{'='*60}")
        print(f"  TRIAGE SUMMARY — {len(alerts)} alert(s)")
        print(f"{'='*60}")
        print(f"  CRITICAL : {by_severity['CRITICAL']}")
        print(f"  HIGH     : {by_severity['HIGH']}")
        print(f"  MEDIUM   : {by_severity['MEDIUM']}")
        print(f"  LOW      : {by_severity['LOW']}")
        print()
        print("  By category:")
        for cat, count in sorted(by_category.items(),
                                 key=lambda x: x[1], reverse=True):
            print(f"    {cat:<30} {count}")
        print(f"{'='*60}")

        # Print CRITICAL and HIGH alerts in detail
        critical_high = [
            a for a in alerts
            if a.get("risk", {}).get("severity") in ("CRITICAL", "HIGH")
        ]
        if critical_high:
            print("\n  CRITICAL / HIGH alerts:")
            for alert in critical_high:
                risk = alert.get("risk", {})
                print(f"  [{risk.get('severity', '?'):8s}] "
                      f"[{alert['rule_id']:12s}] "
                      f"{alert['rule']}")
                print(f"             computer={alert.get('computer', '?')} "
                      f"user={alert.get('user', '?')} "
                      f"score={risk.get('score', 0)}")
                print(f"             {alert.get('detail', '')}")
                tags = alert.get("mitre_tags", [])
                if tags:
                    print(f"             MITRE: {', '.join(tags[:2])}")
                print()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _prepare_for_json(alert: dict) -> dict:
    """Return a JSON-safe copy of an alert - strip raw event lists."""
    result = {k: v for k, v in alert.items() if k != "events"}
    # Summarise triggering events rather than embedding full payloads
    events = alert.get("events", [])
    result["triggering_event_ids"] = [e.get("event_id") for e in events]
    result["triggering_timestamps"] = [
        e["timestamp"].isoformat() if hasattr(e.get("timestamp"), "isoformat")
        else str(e.get("timestamp", ""))
        for e in events
    ]
    return result


def _flatten_for_csv(alert: dict) -> dict:
    """Flatten an enriched alert into a single CSV row."""
    risk = alert.get("risk", {})
    mitre_tags = alert.get("mitre_tags", [])
    return {
        "rule_id":        alert.get("rule_id", ""),
        "rule":           alert.get("rule", ""),
        "category":       alert.get("category", ""),
        "mitre":          alert.get("mitre", ""),
        "sigma_severity": alert.get("sigma_severity", ""),
        "severity":       risk.get("severity", ""),
        "score":          risk.get("score", 0),
        "computer":       alert.get("computer", ""),
        "user":           alert.get("user") or "",
        "ip":             alert.get("ip") or "",
        "count":          alert.get("count", 1),
        "detail":         alert.get("detail", ""),
        "mitre_tags":     " | ".join(mitre_tags),
    }
