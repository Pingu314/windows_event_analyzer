"""Tests for src.report_generator - JSON/CSV export and console summary."""
from __future__ import annotations

import csv
import json

from config.settings import REPORT_CSV_FIELDNAMES
from src.report_generator import ReportGenerator


def test_export_json(tmp_path, sample_alerts):
    reporter = ReportGenerator(report_dir=tmp_path)
    path = reporter.export(sample_alerts, source_path="test.csv")

    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    assert data["meta"]["tool"] == "windows-event-analyzer"
    assert data["meta"]["source"] == "test.csv"
    assert data["meta"]["total_alerts"] == len(sample_alerts)
    assert len(data["alerts"]) == len(sample_alerts)
    for alert in data["alerts"]:
        assert "events" not in alert            # raw payloads stripped
        assert "triggering_event_ids" in alert
        assert "triggering_timestamps" in alert


def test_export_json_min_severity_filter(tmp_path, sample_alerts):
    reporter = ReportGenerator(report_dir=tmp_path)
    path = reporter.export(sample_alerts, min_severity="CRITICAL")

    with open(path, encoding="utf-8") as f:
        data = json.load(f)

    assert data["alerts"]                        # critical fixtures present
    assert all(a["risk"]["severity"] == "CRITICAL" for a in data["alerts"])
    assert data["meta"]["total_alerts"] == len(data["alerts"])


def test_export_csv(tmp_path, sample_alerts):
    reporter = ReportGenerator(report_dir=tmp_path)
    path = reporter.export_csv(sample_alerts)

    with open(path, encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))

    assert len(rows) == len(sample_alerts)
    assert set(rows[0].keys()) == set(REPORT_CSV_FIELDNAMES)
    assert all(r["rule_id"] for r in rows)


def test_print_summary(capsys, sample_alerts):
    ReportGenerator().print_summary(sample_alerts)
    out = capsys.readouterr().out
    assert "TRIAGE SUMMARY" in out
    assert "CRITICAL" in out
    assert "By category:" in out


def test_print_summary_no_alerts(capsys):
    ReportGenerator().print_summary([])
    assert "No alerts detected." in capsys.readouterr().out


def test_print_summary_flags_tor_and_high_risk(capsys, sample_alerts):
    # attach intel to the first CRITICAL/HIGH alerts
    flagged = [a for a in sample_alerts
               if a["risk"]["severity"] in ("CRITICAL", "HIGH")]
    flagged[0]["intel"] = {"is_tor": True, "org": "Tor Exit"}
    if len(flagged) > 1:
        flagged[1]["intel"] = {"is_tor": False, "country": "KP"}

    ReportGenerator().print_summary(sample_alerts)
    out = capsys.readouterr().out
    assert "TOR EXIT NODE" in out
    assert "HIGH-RISK COUNTRY" in out
