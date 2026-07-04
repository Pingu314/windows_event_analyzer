"""
report_generator.py - Report Generator for Windows Event Analyzer

Serialises enriched alerts to JSON, CSV and a self-contained HTML report.
"""
from __future__ import annotations

import csv
import html as _html
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from config.settings import APP_VERSION as _APP_VERSION
from config.settings import DEFAULT_REPORT_DIR as _REPORT_DIR
from config.settings import HIGH_RISK_COUNTRIES as _HIGH_RISK_COUNTRIES
from config.settings import REPORT_CSV_FIELDNAMES as _CSV_FIELDNAMES
from src.correlator import serialise_incident

logger = logging.getLogger(__name__)


class ReportGenerator:
    """Generates JSON and CSV reports from enriched alert lists."""

    def __init__(self, report_dir: str | Path = _REPORT_DIR) -> None:
        self._dir = Path(report_dir)
        self._ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    def _ensure_dir(self) -> None:
        self._dir.mkdir(parents=True, exist_ok=True)

    def export(self, alerts: list[dict], source_path: str = "",
               min_severity: str = "",
               incidents: list[dict] | None = None) -> str:
        """Write alerts (and correlated incidents) to a timestamped JSON file.

        Args:
            alerts: Enriched alert dicts (with 'risk' and 'mitre_tags' keys).
            source_path: Path to the source of the alerts.
            min_severity: Minimum severity level to include in the report.
            incidents: Optional incident list from correlator.correlate().

        Returns:
            Path to the written file as a string.
        """
        self._ensure_dir()
        path = self._dir / f"report_{self._ts}.json"

        # Serialise - strip non-serialisable 'events' list to avoid
        # dumping full event payloads into the report by default
        if min_severity:
            _order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
            alerts = [a for a in alerts
                      if _order.get(a.get("risk", {}).get("severity", "LOW"), 0)
                      >= _order.get(min_severity, 0)]
        serialisable = [_prepare_for_json(a) for a in alerts]
        output = {
            "meta": {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "source": source_path,
                "total_alerts": len(alerts),
                "total_incidents": len(incidents or []),
                "tool": "windows-event-analyzer",
                "version": _APP_VERSION,
            },
            "incidents": [serialise_incident(i) for i in (incidents or [])],
            "alerts": serialisable,
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(output, f, indent=2, default=str)

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

    def print_summary(self, alerts: list[dict],
                      incidents: list[dict] | None = None) -> None:
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
        print(f"  TRIAGE SUMMARY - {len(alerts)} alert(s)")
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

        if incidents:
            print(f"\n  INCIDENTS ({len(incidents)}):")
            for inc in incidents:
                entities = ", ".join((inc["users"] + inc["ips"])[:3]) or \
                    ", ".join(inc["computers"][:2]) or "unknown"
                start = inc["start"].strftime("%H:%M") if inc["start"] else "?"
                end = inc["end"].strftime("%H:%M") if inc["end"] else "?"
                print(f"  [{inc['severity']:8s}] {inc['incident_id']}  "
                      f"score={inc['score']:<3d} "
                      f"{inc['alert_count']} alerts  {start}-{end}  "
                      f"{entities}")
                print(f"             categories: "
                      f"{', '.join(inc['categories'])}")
            print()

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
                intel = alert.get("intel", {})
                if intel.get("is_tor"):
                    print(f"             ⚠  TOR EXIT NODE: {intel.get('org', '')}")
                elif intel.get("country") in _HIGH_RISK_COUNTRIES:
                    print(f"             ⚠  HIGH-RISK COUNTRY: {intel.get('country')}")
                print()

    def export_html(self, alerts: list[dict],
                    incidents: list[dict] | None = None,
                    source_path: str = "") -> str:
        """Write a self-contained HTML triage report (inline CSS, no JS).

        Args:
            alerts: Enriched alert dicts.
            incidents: Optional incident list from correlator.correlate().
            source_path: Analyzed source, shown in the header.

        Returns:
            Path to the written file as a string.
        """
        self._ensure_dir()
        path = self._dir / f"report_{self._ts}.html"
        document = _render_html(alerts, incidents or [], source_path)
        with open(path, "w", encoding="utf-8") as f:
            f.write(document)
        logger.info("HTML report written: %s (%d alerts)", path, len(alerts))
        return str(path)


# ---------------------------------------------------------------------------
# HTML rendering
# ---------------------------------------------------------------------------

# Roles from the validated reference palette (light / dark surface steps).
# Severity chips use the status palette; LOW stays neutral ink - a LOW alert
# is not "good". Category bars use the single sequential blue.
_HTML_CSS = """
:root {
  --surface: #fcfcfb; --card: #f0efec;
  --ink: #0b0b0b; --ink-2: #52514e;
  --bar: #2a78d6; --border: #dddcd7;
  --critical: #d03b3b; --serious: #ec835a;
  --warning: #fab219; --neutral: #52514e;
}
@media (prefers-color-scheme: dark) {
  :root {
    --surface: #1a1a19; --card: #262624;
    --ink: #ffffff; --ink-2: #c3c2b7;
    --bar: #3987e5; --border: #3a3936;
  }
}
* { box-sizing: border-box; margin: 0; }
body { background: var(--surface); color: var(--ink);
       font: 14px/1.5 "Segoe UI", system-ui, sans-serif; padding: 32px;
       max-width: 1100px; margin: 0 auto; }
h1 { font-size: 22px; margin-bottom: 4px; }
h2 { font-size: 16px; margin: 28px 0 12px; }
.meta { color: var(--ink-2); font-size: 12px; margin-bottom: 24px; }
.tiles { display: flex; gap: 12px; flex-wrap: wrap; }
.tile { background: var(--card); border-radius: 8px; padding: 14px 20px;
        min-width: 120px; border-top: 3px solid var(--accent, var(--border)); }
.tile .num { font-size: 26px; font-weight: 700; }
.tile .lbl { font-size: 11px; letter-spacing: .06em; color: var(--ink-2);
             text-transform: uppercase; }
.bars { display: grid; grid-template-columns: 170px 1fr 40px; gap: 6px 10px;
        align-items: center; }
.bars .name { font-size: 13px; text-align: right; color: var(--ink-2);
              overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.bars .track { background: var(--card); border-radius: 4px; height: 14px; }
.bars .fill { background: var(--bar); border-radius: 4px; height: 14px;
              min-width: 2px; }
.bars .val { font-variant-numeric: tabular-nums; font-size: 13px; }
.chip { display: inline-block; padding: 1px 8px; border-radius: 10px;
        font-size: 11px; font-weight: 600; color: #fff; }
.chip.CRITICAL { background: var(--critical); }
.chip.HIGH { background: var(--serious); }
.chip.MEDIUM { background: var(--warning); color: #1a1a19; }
.chip.LOW { background: var(--neutral); }
.card { background: var(--card); border-radius: 8px; padding: 16px 20px;
        margin-bottom: 14px; }
.card .head { display: flex; gap: 10px; align-items: baseline;
              flex-wrap: wrap; margin-bottom: 8px; }
.card .head .id { font-weight: 700; }
.card .facts { color: var(--ink-2); font-size: 12px; margin-bottom: 10px; }
.timeline { list-style: none; padding-left: 0; font-size: 13px; }
.timeline li { padding: 2px 0 2px 18px; position: relative; }
.timeline li::before { content: ""; position: absolute; left: 4px; top: 9px;
                       width: 6px; height: 6px; border-radius: 50%;
                       background: var(--bar); }
table { border-collapse: collapse; width: 100%; font-size: 13px; }
th { text-align: left; color: var(--ink-2); font-size: 11px;
     text-transform: uppercase; letter-spacing: .05em; }
th, td { padding: 6px 10px; border-bottom: 1px solid var(--border); }
tbody tr:hover { background: var(--card); }
td.num { font-variant-numeric: tabular-nums; }
.note { color: var(--ink-2); font-size: 12px; margin-top: 8px; }
"""

_SEVERITY_TILE_ACCENTS = {
    "CRITICAL": "var(--critical)",
    "HIGH":     "var(--serious)",
    "MEDIUM":   "var(--warning)",
    "LOW":      "var(--neutral)",
}

_MAX_HTML_ALERT_ROWS = 100


def _render_html(alerts: list[dict], incidents: list[dict],
                 source_path: str) -> str:
    esc = _html.escape
    by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    by_category: dict[str, int] = {}
    for alert in alerts:
        sev = alert.get("risk", {}).get("severity", "LOW")
        by_severity[sev] = by_severity.get(sev, 0) + 1
        cat = alert.get("category", "Unknown")
        by_category[cat] = by_category.get(cat, 0) + 1

    tiles = "".join(
        f'<div class="tile" style="--accent:{_SEVERITY_TILE_ACCENTS[sev]}">'
        f'<div class="num">{by_severity[sev]}</div>'
        f'<div class="lbl">{sev}</div></div>'
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
    )
    tiles += (f'<div class="tile"><div class="num">{len(incidents)}</div>'
              f'<div class="lbl">Incidents</div></div>')

    max_count = max(by_category.values(), default=1)
    bars = "".join(
        f'<div class="name" title="{esc(cat)}">{esc(cat)}</div>'
        f'<div class="track"><div class="fill" '
        f'style="width:{count / max_count * 100:.0f}%"></div></div>'
        f'<div class="val">{count}</div>'
        for cat, count in sorted(by_category.items(),
                                 key=lambda x: x[1], reverse=True)
    )

    incident_cards = "".join(_render_incident(i) for i in incidents) or \
        '<p class="note">No multi-alert incidents correlated.</p>'

    ranked = sorted(alerts, key=lambda a: a.get("risk", {}).get("score", 0),
                    reverse=True)
    rows = "".join(
        f'<tr><td><span class="chip '
        f'{esc(a.get("risk", {}).get("severity", "LOW"))}">'
        f'{esc(a.get("risk", {}).get("severity", "LOW"))}</span></td>'
        f'<td class="num">{a.get("risk", {}).get("score", 0)}</td>'
        f'<td>{esc(a.get("rule_id", ""))}</td>'
        f'<td>{esc(a.get("rule", ""))}</td>'
        f'<td>{esc(a.get("computer", "") or "")}</td>'
        f'<td>{esc(a.get("user") or "-")}</td>'
        f'<td>{esc(a.get("ip") or "-")}</td>'
        f'<td>{esc((a.get("detail") or "")[:120])}</td></tr>'
        for a in ranked[:_MAX_HTML_ALERT_ROWS]
    )
    truncated = (f'<p class="note">Showing top {_MAX_HTML_ALERT_ROWS} of '
                 f'{len(alerts)} alerts by score - full list in the JSON '
                 f'report.</p>' if len(alerts) > _MAX_HTML_ALERT_ROWS else "")

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    source = f" &middot; source: {esc(source_path)}" if source_path else ""
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Triage Report - windows-event-analyzer</title>
<style>{_HTML_CSS}</style></head>
<body>
<h1>Windows Event Analyzer - Triage Report</h1>
<p class="meta">generated {generated} &middot; v{esc(_APP_VERSION)}{source}
 &middot; {len(alerts)} alert(s)</p>
<div class="tiles">{tiles}</div>
<h2>Alerts by category</h2>
<div class="bars">{bars}</div>
<h2>Incidents</h2>
{incident_cards}
<h2>Alerts</h2>
<table>
<thead><tr><th>Severity</th><th>Score</th><th>Rule ID</th><th>Rule</th>
<th>Computer</th><th>User</th><th>Source IP</th><th>Detail</th></tr></thead>
<tbody>{rows}</tbody>
</table>
{truncated}
</body></html>
"""


def _render_incident(incident: dict) -> str:
    esc = _html.escape
    start = incident["start"].strftime("%Y-%m-%d %H:%M") if incident["start"] else "?"
    end = incident["end"].strftime("%H:%M") if incident["end"] else "?"
    entities = ", ".join(incident["users"] + incident["ips"]) or \
        ", ".join(incident["computers"]) or "unknown"

    steps = []
    seen_rules: set[str] = set()
    for alert in incident["alerts"]:
        if alert["rule_id"] in seen_rules:
            continue
        seen_rules.add(alert["rule_id"])
        events = alert.get("events") or []
        ts = min((e["timestamp"] for e in events if e.get("timestamp")),
                 default=None)
        time_str = ts.strftime("%H:%M") if ts else "--:--"
        steps.append(f"<li><strong>{time_str}</strong> "
                     f"{esc(alert.get('rule', ''))} "
                     f"<span class='note'>({esc(alert['rule_id'])})</span></li>")

    return f"""<div class="card">
<div class="head">
  <span class="chip {esc(incident['severity'])}">{esc(incident['severity'])}</span>
  <span class="id">{esc(incident['incident_id'] or '')}</span>
  <span>score {incident['score']}</span>
  <span class="note">{incident['alert_count']} alerts &middot;
   {start} - {end}</span>
</div>
<div class="facts">entities: {esc(entities)}<br>
categories: {esc(', '.join(incident['categories']))}<br>
MITRE: {esc(', '.join(incident['mitre_tags'][:4]))}</div>
<ul class="timeline">{''.join(steps)}</ul>
</div>"""


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
        "rule_id":          alert.get("rule_id", ""),
        "rule":             alert.get("rule", ""),
        "category":         alert.get("category", ""),
        "mitre":            alert.get("mitre", ""),
        "sigma_severity":   alert.get("sigma_severity", ""),
        "severity":         risk.get("severity", ""),
        "score":            risk.get("score", 0),
        "computer":         alert.get("computer", ""),
        "user":             alert.get("user") or "",
        "ip":               alert.get("ip") or "",
        "count":            alert.get("count", 1),
        "detail":           alert.get("detail", ""),
        "mitre_tags":       " | ".join(mitre_tags),
        "intel_country":    alert.get("intel", {}).get("country") or "",
        "intel_org":        alert.get("intel", {}).get("org") or "",
        "intel_is_tor":     alert.get("intel", {}).get("is_tor", False),
        "user_context":     alert.get("user_context", {}).get("account_type") or "",
        "computer_context": alert.get("computer_context", {}).get("computer_type") or "",
    }
