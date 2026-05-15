"""
dashboard.py - Flask REST API for Windows Event Analyzer

Endpoints:
    GET  /                      Welcome + endpoint listing
    GET  /health                Health check
    GET  /alerts                Alerts from sample data (cached)
    GET  /alerts/summary        Severity counts and category breakdown
    GET  /alerts/<rule_id>      All alerts matching a specific rule
    GET  /alerts/severity/<lvl> Alerts filtered by severity
    POST /analyze               Analyze uploaded .evtx, .csv or .json file(s)
    DELETE /cache               Clear cached sample-data alerts

Limitations (documented):
    - No authentication - local/portfolio use only
    - No rate limiting on /analyze
    - In-memory cache only - cleared on restart
    - Single-worker Flask dev server - not for production

Usage:
    python -m src.dashboard
    # or via Flask CLI:
    flask --app src.dashboard run
"""
from __future__ import annotations

import logging
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from flask import Flask, Response, jsonify, request

from config.settings import APP_VERSION, SUPPORTED_LOG_EXTENSIONS
from src.enricher import AlertContextEnricher
from src.main import run_pipeline, run_pipeline_multi

app = Flask(__name__)
logger = logging.getLogger(__name__)

_cached_alerts: list[dict] | None = None
_cache_source: str = ""
_cache_generated_at: str = ""

_SAMPLE_LOG = (
    Path(__file__).parent.parent / "data" / "sample_logs" / "security.csv"
)

_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------

def _get_cached_alerts() -> list[dict]:
    global _cached_alerts, _cache_source, _cache_generated_at
    if _cached_alerts is None:
        if _SAMPLE_LOG.exists():
            enricher = AlertContextEnricher()
            _cached_alerts = run_pipeline(str(_SAMPLE_LOG), enricher=enricher)
            _cache_source = str(_SAMPLE_LOG)
            _cache_generated_at = datetime.now(timezone.utc).isoformat()
        else:
            logger.warning("Sample log not found: %s", _SAMPLE_LOG)
            _cached_alerts = []
    return _cached_alerts


def _int_param(name: str) -> int | None:
    val = request.args.get(name)
    try:
        return int(val) if val is not None else None
    except ValueError:
        return None


def _override_kwargs() -> dict:
    return {
        "brute_force_threshold": _int_param("brute_threshold"),
        "brute_force_window":    _int_param("brute_window"),
        "spray_threshold":       _int_param("spray_threshold"),
        "spray_window":          _int_param("spray_window"),
        "lateral_threshold":     _int_param("lateral_threshold"),
        "lateral_window":        _int_param("lateral_window"),
    }


def _serialise(alerts: list[dict]) -> list[dict]:
    """Strip non-serialisable fields for JSON response."""
    result = []
    for alert in alerts:
        row = {k: v for k, v in alert.items() if k != "events"}
        row["triggering_event_ids"] = [
            e.get("event_id") for e in alert.get("events", [])
        ]
        result.append(row)
    return result


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def home() -> Response:
    """Return welcome message, endpoint listing and tool version."""
    return jsonify({
        "tool":    "windows-event-analyzer",
        "version": APP_VERSION,
        "message": "Dashboard running. See /alerts for sample data.",
        "endpoints": {
            "GET  /":                    "This page",
            "GET  /health":              "Health check",
            "GET  /alerts":              "Alerts from sample data (cached)",
            "GET  /alerts/summary":      "Severity and category breakdown",
            "GET  /alerts/<rule_id>":    "Alerts for a specific rule ID",
            "GET  /alerts/severity/<lvl>": "Alerts filtered by severity",
            "POST /analyze":             "Analyze uploaded .evtx/.csv/.json file(s)",
            "DELETE /cache":             "Clear cached sample-data alerts",
        },
        "analyze_params": {
            "file":              "multipart/form-data - one or more log files",
            "brute_threshold":   "Brute force logon threshold",
            "brute_window":      "Brute force time window (minutes)",
            "spray_threshold":   "Password spray account threshold",
            "spray_window":      "Password spray time window (minutes)",
            "lateral_threshold": "Lateral movement target threshold",
            "lateral_window":    "Lateral movement time window (minutes)",
        },
        "limitations": [
            "No authentication - local/portfolio use only",
            "No rate limiting",
            "In-memory cache - cleared on restart",
        ],
    })


@app.route("/health")
def health() -> Response:
    """Health check endpoint."""
    return jsonify({
        "status":       "ok",
        "cache_loaded": _cached_alerts is not None,
        "cache_size":   len(_cached_alerts) if _cached_alerts else 0,
        "timestamp":    datetime.now(timezone.utc).isoformat(),
    })


@app.route("/alerts")
def alerts() -> Response:
    """Return all cached alerts from sample data.

    Optional query params:
        limit (int): Maximum number of alerts to return.
        offset (int): Offset for pagination.
    """
    data = _get_cached_alerts()
    limit = _int_param("limit")
    offset = _int_param("offset") or 0

    page = data[offset:offset + limit] if limit else data[offset:]

    return jsonify({
        "total_alerts":       len(data),
        "returned":           len(page),
        "offset":             offset,
        "cache_source":       _cache_source,
        "cache_generated_at": _cache_generated_at,
        "alerts":             _serialise(page),
    })


@app.route("/alerts/summary")
def alerts_summary() -> Response:
    """Return severity counts, category breakdown and top rules."""
    data = _get_cached_alerts()

    by_severity: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    by_category: dict[str, int] = {}
    by_rule: dict[str, int] = {}
    tor_alerts = 0
    high_risk_country_alerts = 0

    for alert in data:
        sev = alert.get("risk", {}).get("severity", "LOW")
        by_severity[sev] = by_severity.get(sev, 0) + 1

        cat = alert.get("category", "Unknown")
        by_category[cat] = by_category.get(cat, 0) + 1

        rule_id = alert.get("rule_id", "unknown")
        by_rule[rule_id] = by_rule.get(rule_id, 0) + 1

        intel = alert.get("intel", {})
        if intel.get("is_tor"):
            tor_alerts += 1
        if intel.get("is_high_risk_country"):
            high_risk_country_alerts += 1

    return jsonify({
        "total_alerts":             len(data),
        "by_severity":              by_severity,
        "by_category":              by_category,
        "top_rules":                sorted(
            by_rule.items(), key=lambda x: x[1], reverse=True
        )[:10],
        "tor_source_alerts":        tor_alerts,
        "high_risk_country_alerts": high_risk_country_alerts,
    })


@app.route("/alerts/severity/<string:level>")
def alerts_by_severity(level: str) -> Response:
    """Return alerts filtered by severity level.

    Args:
        level: One of CRITICAL, HIGH, MEDIUM, LOW (case-insensitive).
    """
    level = level.upper()
    if level not in _SEVERITY_ORDER:
        return jsonify({
            "error": f"Invalid severity '{level}'. "
                     f"Valid: CRITICAL, HIGH, MEDIUM, LOW"
        }), 400

    data = _get_cached_alerts()
    matched = [
        a for a in data
        if a.get("risk", {}).get("severity") == level
    ]
    return jsonify({
        "severity":     level,
        "total_alerts": len(matched),
        "alerts":       _serialise(matched),
    })


@app.route("/alerts/<string:rule_id>")
def alerts_by_rule(rule_id: str) -> Response:
    """Return all alerts matching a specific rule ID.

    Args:
        rule_id: Rule ID string e.g. 'brute-001', 'evasion-001'.
    """
    data = _get_cached_alerts()
    matched = [a for a in data if a.get("rule_id") == rule_id]
    return jsonify({
        "rule_id":      rule_id,
        "total_alerts": len(matched),
        "alerts":       _serialise(matched),
    })


@app.route("/analyze", methods=["POST"])
def analyze() -> tuple[Response, int]:
    """Analyze one or more uploaded log files.

    Accepts multipart/form-data with one or more 'file' fields.
    Supported formats: .evtx, .csv, .json
    Multiple files are merged before detection - cross-file correlation applies.

    Optional query parameters:
        brute_threshold, brute_window, spray_threshold, spray_window,
        lateral_threshold, lateral_window

    Returns:
        JSON with alerts, total_alerts, files_processed, summary.
    """
    files = request.files.getlist("file")

    if not files or all(not f.filename for f in files):
        return jsonify({
            "error": "No files provided. Send one or more .evtx, .csv or .json files."
        }), 400

    invalid = [
        f.filename for f in files
        if f.filename and Path(f.filename).suffix.lower()
        not in SUPPORTED_LOG_EXTENSIONS
    ]
    if invalid:
        return jsonify({
            "error": f"Unsupported file type(s): {invalid}. "
                     f"Allowed: {sorted(SUPPORTED_LOG_EXTENSIONS)}"
        }), 400

    tmp_paths: list[tuple[str, str]] = []
    try:
        for f in files:
            if not f.filename:
                continue
            suffix = Path(f.filename).suffix.lower()
            tmp = tempfile.NamedTemporaryFile(
                mode="wb", suffix=suffix, delete=False
            )
            f.save(tmp)
            tmp.close()
            tmp_paths.append((tmp.name, f.filename))

        path_objects = [Path(p) for p, _ in tmp_paths]
        filenames = [name for _, name in tmp_paths]
        kwargs = _override_kwargs()
        enricher = AlertContextEnricher()

        if len(path_objects) == 1:
            result_alerts = run_pipeline(
                str(path_objects[0]), enricher=enricher, **kwargs
            )
        else:
            result_alerts = run_pipeline_multi(
                path_objects, enricher=enricher, **kwargs
            )

        by_severity: dict[str, int] = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0
        }
        for alert in result_alerts:
            sev = alert.get("risk", {}).get("severity", "LOW")
            by_severity[sev] = by_severity.get(sev, 0) + 1

        return jsonify({
            "files_processed": filenames,
            "total_alerts":    len(result_alerts),
            "summary":         by_severity,
            "alerts":          _serialise(result_alerts),
        }), 200

    except Exception as e:
        logger.exception("Pipeline failed for uploaded file(s): %s", e)
        return jsonify({"error": str(e)}), 500

    finally:
        for tmp_path, _ in tmp_paths:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass


@app.route("/cache", methods=["DELETE"])
def clear_cache() -> tuple[Response, int]:
    """Clear the cached sample-data alerts."""
    global _cached_alerts, _cache_source, _cache_generated_at
    _cached_alerts = None
    _cache_source = ""
    _cache_generated_at = ""
    return jsonify({
        "message": "Cache cleared. Next /alerts call re-runs the pipeline."
    }), 200


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    host = os.environ.get("DASHBOARD_HOST", "127.0.0.1")
    port = int(os.environ.get("DASHBOARD_PORT", "5000"))
    debug = os.environ.get("DASHBOARD_DEBUG", "false").lower() == "true"
    logging.basicConfig(level=logging.INFO)
    logger.info("Starting dashboard on %s:%d", host, port)
    app.run(host=host, port=port, debug=debug)
