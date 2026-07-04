"""Tests for src.main - CLI entrypoint, input collection, pipeline wiring."""
from __future__ import annotations

import sys

import pytest

from src.main import (
    collect_log_files,
    collect_log_files_recursive,
    main,
    run_pipeline,
    run_pipeline_multi,
)


def test_collect_log_files_single_file(sample_csv_path):
    assert collect_log_files(sample_csv_path) == [sample_csv_path]


def test_collect_log_files_unsupported(tmp_path):
    txt = tmp_path / "notes.txt"
    txt.write_text("x")
    assert collect_log_files(txt) == []


def test_collect_log_files_missing(tmp_path):
    assert collect_log_files(tmp_path / "nope") == []


def test_collect_log_files_directory(sample_csv_path, sample_jsonl_path):
    # both fixtures live in the same tmp_path directory
    found = collect_log_files(sample_csv_path.parent)
    assert sample_csv_path in found
    assert sample_jsonl_path in found


def test_collect_log_files_recursive(tmp_path, sample_csv_path):
    nested = tmp_path / "sub" / "deeper"
    nested.mkdir(parents=True)
    target = nested / "deep.csv"
    target.write_text(sample_csv_path.read_text())
    found = collect_log_files_recursive(tmp_path)
    assert target in found


def test_run_pipeline(sample_csv_path):
    alerts = run_pipeline(sample_csv_path)
    assert alerts
    for alert in alerts:
        assert "risk" in alert
        assert "mitre_tags" in alert
    assert any(a["rule_id"] == "evasion-001" for a in alerts)


def test_run_pipeline_threshold_override(sample_csv_path):
    # sky-high thresholds: only single-event rules remain
    alerts = run_pipeline(sample_csv_path, brute_force_threshold=99)
    assert all(a["rule_id"] != "brute-001" for a in alerts)


def test_run_pipeline_multi(sample_csv_path, sample_jsonl_path):
    alerts = run_pipeline_multi([sample_csv_path, sample_jsonl_path])
    assert alerts
    assert all("risk" in a for a in alerts)


def test_main_end_to_end(sample_csv_path, tmp_path, monkeypatch, capsys):
    out_dir = tmp_path / "out"
    monkeypatch.setattr(sys, "argv", [
        "evtx-analyze", str(sample_csv_path),
        "--output", str(out_dir), "--csv",
    ])
    main()
    out = capsys.readouterr().out
    assert "TRIAGE SUMMARY" in out
    assert list(out_dir.glob("report_*.json"))
    assert list(out_dir.glob("report_*.csv"))


def test_main_no_export(sample_csv_path, tmp_path, monkeypatch, capsys):
    out_dir = tmp_path / "out"
    monkeypatch.setattr(sys, "argv", [
        "evtx-analyze", str(sample_csv_path),
        "--output", str(out_dir), "--no-export",
    ])
    main()
    assert not out_dir.exists()


def test_main_without_valid_input_exits(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["evtx-analyze", str(tmp_path / "nope.csv")])
    with pytest.raises(SystemExit):
        main()


# ---------------------------------------------------------------------------
# Input flag combinations
# ---------------------------------------------------------------------------


def test_collect_recursive_on_single_file(sample_csv_path):
    assert collect_log_files_recursive(sample_csv_path) == [sample_csv_path]


def test_main_with_logs_flag(sample_csv_path, tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", [
        "evtx-analyze", "--logs", str(sample_csv_path),
        "--output", str(tmp_path / "out"), "--no-export",
    ])
    main()
    assert "TRIAGE SUMMARY" in capsys.readouterr().out


def test_main_with_logs_dir_recursive(sample_csv_path, tmp_path, monkeypatch, capsys):
    root = tmp_path / "logs"
    nested = root / "sub"
    nested.mkdir(parents=True)
    (nested / "a.csv").write_text(sample_csv_path.read_text())
    (root / "b.csv").write_text(sample_csv_path.read_text())

    monkeypatch.setattr(sys, "argv", [
        "evtx-analyze", "--logs-dir", str(root), "--recursive",
        "--output", str(tmp_path / "out"), "--no-export",
    ])
    main()
    out = capsys.readouterr().out
    assert "TRIAGE SUMMARY" in out


def test_main_positional_directory_recursive(sample_csv_path, tmp_path,
                                             monkeypatch, capsys):
    root = tmp_path / "logs"
    nested = root / "deep"
    nested.mkdir(parents=True)
    (nested / "a.csv").write_text(sample_csv_path.read_text())

    monkeypatch.setattr(sys, "argv", [
        "evtx-analyze", str(root), "--recursive",
        "--output", str(tmp_path / "out"), "--no-export",
    ])
    main()
    assert "TRIAGE SUMMARY" in capsys.readouterr().out


def test_main_export_failure_is_reported(sample_csv_path, tmp_path,
                                         monkeypatch, capsys):
    # --output points at an existing *file*, so mkdir raises OSError
    blocker = tmp_path / "blocked"
    blocker.write_text("i am a file")
    monkeypatch.setattr(sys, "argv", [
        "evtx-analyze", str(sample_csv_path), "--output", str(blocker),
    ])
    main()
    assert "Could not write JSON report" in capsys.readouterr().out
