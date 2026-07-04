"""
sigma_loader.py - Sigma YAML rule loader for Windows Event Analyzer

Loads Sigma detection rules (https://sigmahq.io) from YAML files and
converts the supported subset into the internal rule format consumed by
detector.run_all_detections(sigma_rules=...).

Supported Sigma subset (rules outside it are skipped with a warning):
  - logsource.product: windows (any service)
  - detection with exactly one selection, condition: "selection"
  - selection fields:
        EventID: 4688 | [4688, 4689]        (required)
        Field|contains: value | [values]     (OR within the list)
        Field: value | [values]              (exact match, OR within list)
  - level: informational|low|medium|high|critical
  - tags: attack.tXXXX(.YYY) → MITRE technique, attack.<tactic> ignored

This is intentionally a mini-engine: enough to run community rules of the
"EventID + field filter" shape, which covers the majority of Windows
Security Sigma rules, without pulling in a full backend.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

import yaml

logger = logging.getLogger(__name__)

_LEVELS = {"informational", "low", "medium", "high", "critical"}


def load_sigma_rules(path: str | Path) -> list[dict]:
    """Load all Sigma YAML rules from a file or directory.

    Args:
        path: A .yml/.yaml file or a directory scanned non-recursively.

    Returns:
        List of converted internal rule dicts (possibly empty). Unsupported
        or malformed rules are skipped and logged, never fatal.
    """
    p = Path(path)
    if not p.exists():
        logger.warning("Sigma rules path does not exist: %s", p)
        return []

    files = ([p] if p.is_file()
             else sorted(f for f in p.iterdir()
                         if f.suffix.lower() in (".yml", ".yaml")))

    rules = []
    for file in files:
        rule = _load_file(file)
        if rule:
            rules.append(rule)

    logger.info("Loaded %d Sigma rule(s) from %s", len(rules), p)
    return rules


def _load_file(file: Path) -> dict | None:
    try:
        with open(file, encoding="utf-8") as f:
            doc = yaml.safe_load(f)
    except (yaml.YAMLError, OSError) as e:
        logger.warning("Skipping Sigma rule %s: unreadable YAML (%s)",
                       file.name, e)
        return None

    if not isinstance(doc, dict):
        logger.warning("Skipping Sigma rule %s: not a mapping", file.name)
        return None
    return convert_sigma_rule(doc, source=file.stem)


def convert_sigma_rule(doc: dict, source: str = "rule") -> dict | None:
    """Convert one parsed Sigma document to the internal rule format.

    Returns None (with a warning) when the rule uses unsupported features.
    """
    title = doc.get("title") or source
    detection = doc.get("detection")
    if not isinstance(detection, dict):
        logger.warning("Skipping Sigma rule '%s': no detection block", title)
        return None

    condition = str(detection.get("condition", "")).strip().lower()
    if condition != "selection":
        logger.warning(
            "Skipping Sigma rule '%s': unsupported condition '%s' "
            "(only 'selection' is supported)", title, condition)
        return None

    selection = detection.get("selection")
    if not isinstance(selection, dict):
        logger.warning("Skipping Sigma rule '%s': no selection block", title)
        return None

    event_ids = _as_list(selection.get("EventID"))
    try:
        event_ids = [int(e) for e in event_ids]
    except (TypeError, ValueError):
        event_ids = []
    if not event_ids:
        logger.warning(
            "Skipping Sigma rule '%s': selection needs an EventID", title)
        return None

    contains: dict[str, list] = {}
    equals: dict[str, list] = {}
    for key, value in selection.items():
        if key == "EventID":
            continue
        values = _as_list(value)
        if key.endswith("|contains"):
            contains[key.removesuffix("|contains")] = values
        elif "|" in key:
            logger.warning(
                "Skipping Sigma rule '%s': unsupported modifier in '%s'",
                title, key)
            return None
        else:
            equals[key] = values

    level = str(doc.get("level", "medium")).lower()
    if level not in _LEVELS:
        level = "medium"

    return {
        "rule_id":        f"sigma-{_slug(doc.get('id') or source)}",
        "rule":           title,
        "category":       "Sigma",
        "mitre":          _primary_technique(doc.get("tags") or []),
        "sigma_severity": level,
        "event_ids":      event_ids,
        "match": {
            "event_ids": event_ids,
            "contains":  contains,
            "equals":    equals,
        },
    }


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _as_list(value) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _slug(value: str) -> str:
    """Stable short rule-id suffix from the Sigma id/filename."""
    cleaned = re.sub(r"[^a-z0-9]+", "-", str(value).lower()).strip("-")
    return cleaned[:24] or "unnamed"


def _primary_technique(tags: list) -> str:
    """First attack.tXXXX tag as technique ID, e.g. 'T1059.001'."""
    for tag in tags:
        match = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", str(tag).lower())
        if match:
            return match.group(1).upper()
    return ""
