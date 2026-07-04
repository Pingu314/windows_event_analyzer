"""
correlator.py - Incident correlation for Windows Event Analyzer

Groups related alerts into incidents, the way a fraud-monitoring system
clusters transactions into cases: alerts that share an actor entity
(source IP or user) within a time window belong to one incident.

An incident dict:

    {
        "incident_id":  "INC-001",
        "severity":     "CRITICAL",          # max alert severity
        "score":        100,                 # max score + category bonus
        "alert_count":  12,
        "start":        datetime | None,     # first triggering event
        "end":          datetime | None,     # last triggering event
        "users":        ["svc_backup"],
        "ips":          ["91.240.118.29"],
        "computers":    ["dc01.corp.local"],
        "categories":   ["Authentication", ...],
        "mitre_tags":   [...],               # union, most frequent first
        "rule_ids":     [...],               # in chronological order
        "top_alerts":   [...],               # 3 highest-scoring alert dicts
        "alerts":       [...],               # all member alerts
    }

Alerts that join an incident get an 'incident_id' key; singletons keep
incident_id=None. Only groups with >= INCIDENT_MIN_ALERTS become incidents.
"""
from __future__ import annotations

import logging
from collections import Counter, defaultdict
from datetime import datetime, timedelta

from config.settings import (
    INCIDENT_CATEGORY_BONUS,
    INCIDENT_MIN_ALERTS,
    INCIDENT_WINDOW_MINUTES,
    MAX_SCORE,
)

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def correlate(alerts: list[dict],
              window_minutes: int = INCIDENT_WINDOW_MINUTES) -> list[dict]:
    """Group scored alerts into incidents by shared entity + time proximity.

    Two alerts are linked when they share a non-empty entity (source IP or
    user; computer as fallback for alerts with neither) and their trigger
    times are within window_minutes. Linking is transitive: a spray from an
    IP and a later privilege escalation by the compromised user end up in
    the same incident when a middle alert carries both entities.

    Args:
        alerts: Scored alerts (after risk_scorer.score_all).
        window_minutes: Max gap between linked alerts on the same entity.

    Returns:
        Incident list sorted by score descending. Also stamps
        'incident_id' on every alert in-place.
    """
    for alert in alerts:
        alert["incident_id"] = None
    if not alerts:
        return []

    window = timedelta(minutes=window_minutes)
    times = [_alert_time(a) for a in alerts]

    # Union-find over alert indices
    parent = list(range(len(alerts)))

    def find(i: int) -> int:
        while parent[i] != i:
            parent[i] = parent[parent[i]]
            i = parent[i]
        return i

    def union(i: int, j: int) -> None:
        ri, rj = find(i), find(j)
        if ri != rj:
            parent[rj] = ri

    # Link alerts that share an entity and are close in time. Per entity,
    # only consecutive alerts (sorted by time) need linking - transitivity
    # closes the chain.
    by_entity: dict[str, list[int]] = defaultdict(list)
    for idx, alert in enumerate(alerts):
        for entity in _entities(alert):
            by_entity[entity].append(idx)

    for indices in by_entity.values():
        indices.sort(key=lambda i: times[i] or datetime.min)
        for a, b in zip(indices, indices[1:], strict=False):
            ta, tb = times[a], times[b]
            if ta is None or tb is None or (tb - ta) <= window:
                union(a, b)

    groups: dict[int, list[int]] = defaultdict(list)
    for idx in range(len(alerts)):
        groups[find(idx)].append(idx)

    incidents = []
    for indices in groups.values():
        if len(indices) < INCIDENT_MIN_ALERTS:
            continue
        members = sorted(
            (alerts[i] for i in indices),
            key=lambda a: _alert_time(a) or datetime.min,
        )
        incidents.append(_build_incident(members))

    incidents.sort(key=lambda i: (i["score"],
                                  _SEVERITY_ORDER.get(i["severity"], 0),
                                  i["alert_count"]),
                   reverse=True)
    for n, incident in enumerate(incidents, 1):
        incident["incident_id"] = f"INC-{n:03d}"
        for alert in incident["alerts"]:
            alert["incident_id"] = incident["incident_id"]

    logger.info("Correlated %d alert(s) into %d incident(s)",
                sum(i["alert_count"] for i in incidents), len(incidents))
    return incidents


def serialise_incident(incident: dict) -> dict:
    """JSON-safe incident copy - drops member alert payloads."""
    result = {k: v for k, v in incident.items()
              if k not in ("alerts", "top_alerts")}
    result["start"] = incident["start"].isoformat() if incident["start"] else None
    result["end"] = incident["end"].isoformat() if incident["end"] else None
    result["top_alerts"] = [
        {
            "rule_id":  a.get("rule_id"),
            "rule":     a.get("rule"),
            "severity": a.get("risk", {}).get("severity"),
            "score":    a.get("risk", {}).get("score"),
            "detail":   a.get("detail"),
        }
        for a in incident["top_alerts"]
    ]
    return result


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _alert_time(alert: dict) -> datetime | None:
    """Trigger time of an alert = timestamp of its first event."""
    events = alert.get("events") or []
    timestamps = [e["timestamp"] for e in events if e.get("timestamp")]
    return min(timestamps) if timestamps else None


def _entities(alert: dict) -> list[str]:
    """Linking entities of an alert - actor first, host as fallback."""
    entities = []
    if alert.get("ip"):
        entities.append(f"ip:{alert['ip']}")
    if alert.get("user"):
        entities.append(f"user:{alert['user']}")
    if not entities and alert.get("computer"):
        entities.append(f"host:{alert['computer']}")
    return entities


def _build_incident(members: list[dict]) -> dict:
    times = [t for t in (_alert_time(a) for a in members) if t]
    severities = [a.get("risk", {}).get("severity", "LOW") for a in members]
    scores = [a.get("risk", {}).get("score", 0) for a in members]
    categories = sorted({a.get("category", "Unknown") for a in members})

    mitre_counts: Counter[str] = Counter()
    for alert in members:
        mitre_counts.update(alert.get("mitre_tags", []))

    # More distinct attack categories in one incident = broader kill chain
    score = min(MAX_SCORE,
                max(scores, default=0)
                + INCIDENT_CATEGORY_BONUS * (len(categories) - 1))

    top_alerts = sorted(members,
                        key=lambda a: a.get("risk", {}).get("score", 0),
                        reverse=True)[:3]

    return {
        "incident_id": None,   # assigned after sorting
        "severity":    max(severities,
                           key=lambda s: _SEVERITY_ORDER.get(s, 0)),
        "score":       score,
        "alert_count": len(members),
        "start":       min(times) if times else None,
        "end":         max(times) if times else None,
        "users":       sorted({a["user"] for a in members if a.get("user")}),
        "ips":         sorted({a["ip"] for a in members if a.get("ip")}),
        "computers":   sorted({a["computer"] for a in members
                               if a.get("computer")}),
        "categories":  categories,
        "mitre_tags":  [t for t, _ in mitre_counts.most_common(5)],
        "rule_ids":    [a["rule_id"] for a in members],
        "top_alerts":  top_alerts,
        "alerts":      members,
    }
