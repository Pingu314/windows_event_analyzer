"""
parser.py - Windows Security Event Log Parser

Supports three input formats:
  - EVTX: native Windows binary format via python-evtx
  - CSV:  exported from Windows Event Viewer or PowerShell Get-WinEvent
  - JSON: JSONL format (mixed channel datasets, PowerShell, Sentinel, generic)

Both formats are normalised to the same event dict schema:

    {
        "event_id":     int,
        "timestamp":    datetime (UTC-aware),
        "source":       str,
        "computer":     str,
        "user":         str | None,
        "level":        str,
        "message":      str,
        "logon_type":   int | None,
        "ip_address":   str | None,
        "process_name": str | None,
        "task_name":    str | None,
        "service_name": str | None,
        "raw":          dict,      # original unparsed fields
    }
"""
from __future__ import annotations

import csv
import json
import logging
import xml.etree.ElementTree as ET
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path

from config.settings import CSV_COLUMN_ALIASES, JSON_FIELD_ALIASES

try:
    import Evtx.Evtx as _evtx_lib  # noqa: N813
    _EVTX_AVAILABLE = True
except ImportError:
    _EVTX_AVAILABLE = False

logger = logging.getLogger(__name__)

# EVTX XML namespace
_EVTX_NS = "http://schemas.microsoft.com/win/2004/08/events/event"


def parse(path: str | Path) -> list[dict]:
    """Parse a Windows Security log file (EVTX, CSV, JSON).

    Args:
        path: Path to .evtx, .csv or .json file.

    Returns:
        List of normalised event dicts, sorted by timestamp ascending.

    Raises:
        ValueError: If file extension is not .evtx, .csv or .json.
        FileNotFoundError: If path does not exist.
        ImportError: If .evtx requested but python-evtx not installed.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Log file not found: {p}")

    suffix = p.suffix.lower()
    if suffix == ".evtx":
        events = list(_parse_evtx(p))
    elif suffix == ".csv":
        events = list(_parse_csv(p))
    elif suffix == ".json":
        events = list(_parse_jsonl(p))
    else:
        raise ValueError(f"Unsupported file type: {suffix}. Expected .evtx, .csv or .json")

    # Sort by timestamp - critical for sequence-based detection rules
    events.sort(key=lambda e: e["timestamp"])
    logger.info("Parsed %d events from %s", len(events), p.name)
    return events


def parse_many(paths: list[str | Path]) -> list[dict]:
    """Parse multiple log files and merge into a single sorted event stream.

    Args:
        paths: List of .evtx or .csv file paths.

    Returns:
        Merged, timestamp-sorted list of normalised event dicts.
    """
    all_events: list[dict] = []
    for path in paths:
        try:
            events = parse(path)
            logger.info("  %s: %d events", Path(path).name, len(events))
            all_events.extend(events)
        except Exception as e:
            logger.warning("  Skipping %s: %s", Path(path).name, e)

    all_events.sort(key=lambda e: e["timestamp"])
    logger.info("Total: %d events across %d file(s)", len(all_events), len(paths))
    return all_events


# ---------------------------------------------------------------------------
# EVTX parser
# ---------------------------------------------------------------------------

def _parse_evtx(path: Path) -> Iterator[dict]:
    """Parse a native .evtx file using python-evtx.

    Raises:
        ImportError: If python-evtx is not installed.
    """
    if not _EVTX_AVAILABLE:
        raise ImportError(
            "python-evtx is required for EVTX parsing. "
            "Install with: pip install python-evtx"
        )

    try:
        with _evtx_lib.Evtx(str(path)) as log:
            for record in log.records():
                try:
                    xml_str = record.xml()
                    event = _parse_evtx_record_xml(xml_str)
                    if event:
                        yield event
                except Exception as e:
                    logger.debug("Skipping malformed EVTX record: %s", e)
    except Exception as e:
        logger.error("Failed to open EVTX file %s: %s", path, e)
        raise


def _parse_evtx_record_xml(xml_str: str) -> dict | None:
    """Parse a single EVTX record XML string into a normalised event dict."""
    try:
        root = ET.fromstring(xml_str)
        ns = {"e": _EVTX_NS}

        system = root.find("e:System", ns)
        if system is None:
            return None

        # Core system fields
        event_id_elem = system.find("e:EventID", ns)
        event_id = int(event_id_elem.text) if event_id_elem is not None else 0

        time_created = system.find("e:TimeCreated", ns)
        timestamp_str = (time_created.get("SystemTime", "")
                         if time_created is not None else "")
        timestamp = _parse_timestamp_evtx(timestamp_str)

        provider = system.find("e:Provider", ns)
        source = (provider.get("Name", "") if provider is not None else "")

        computer_elem = system.find("e:Computer", ns)
        computer = (computer_elem.text or "" if computer_elem is not None else "")

        level_elem = system.find("e:Level", ns)
        level = _level_name(int(level_elem.text or "0")
                            if level_elem is not None else 0)

        # EventData fields
        event_data = root.find("e:EventData", ns)
        data_fields: dict[str, str] = {}
        if event_data is not None:
            for data in event_data.findall("e:Data", ns):
                name = data.get("Name", "")
                value = data.text or ""
                if name:
                    data_fields[name] = value

        # Extract well-known fields from EventData by name
        user = (data_fields.get("SubjectUserName")
                or data_fields.get("TargetUserName")
                or data_fields.get("SamAccountName"))
        ip_address = (data_fields.get("IpAddress")
                      or data_fields.get("SourceAddress"))
        process_name = (data_fields.get("NewProcessName")
                        or data_fields.get("ProcessName"))
        task_name = data_fields.get("TaskName")
        service_name = data_fields.get("ServiceName")
        logon_type_str = data_fields.get("LogonType")
        logon_type = (int(logon_type_str)
                      if logon_type_str and logon_type_str.isdigit() else None)

        message = " | ".join(f"{k}={v}" for k, v in data_fields.items() if v)

        return {
            "event_id":     event_id,
            "timestamp":    timestamp,
            "source":       source,
            "computer":     computer.lower(),
            "user":         _clean_user(user),
            "level":        level,
            "message":      message,
            "logon_type":   logon_type,
            "ip_address":   _clean_ip(ip_address),
            "process_name": _clean_process(process_name),
            "task_name":    task_name,
            "service_name": service_name,
            "raw":          data_fields,
        }
    except Exception as e:
        logger.debug("Failed to parse EVTX XML record: %s", e)
        return None


# ---------------------------------------------------------------------------
# CSV parser
# ---------------------------------------------------------------------------

def _parse_csv(path: Path) -> Iterator[dict]:
    """Parse a Windows Event Viewer CSV export.

    Handles UTF-8 BOM (utf-8-sig) and common encoding issues.
    """
    try:
        with open(path, encoding="utf-8-sig", errors="replace") as f:
            reader = csv.DictReader(f)
            if not reader.fieldnames:
                logger.warning("Empty or headerless CSV: %s", path)
                return

            col_map = _build_column_map(list(reader.fieldnames))

            for row_num, row in enumerate(reader, 2):
                try:
                    event = _parse_csv_row(row, col_map)
                    if event:
                        yield event
                except Exception as e:
                    logger.debug("Skipping malformed CSV row %d: %s", row_num, e)

    except Exception as e:
        logger.error("Failed to read CSV file %s: %s", path, e)
        raise


def _build_column_map(fieldnames: list[str]) -> dict[str, str]:
    """Map canonical field names to actual CSV column headers.

    Uses alias lists from settings.py to handle locale variations.
    """
    col_map: dict[str, str] = {}
    fieldnames_lower = {f.lower(): f for f in fieldnames}

    for canonical, aliases in CSV_COLUMN_ALIASES.items():
        for alias in aliases:
            if alias.lower() in fieldnames_lower:
                col_map[canonical] = fieldnames_lower[alias.lower()]
                break

    return col_map


def _parse_csv_row(row: dict, col_map: dict[str, str]) -> dict | None:
    """Parse a single CSV row into a normalised event dict."""
    def get(field: str) -> str:
        col = col_map.get(field)
        return row.get(col, "").strip() if col else ""

    event_id_str = get("event_id")
    if not event_id_str:
        return None

    try:
        event_id = int(event_id_str)
    except ValueError:
        return None

    timestamp = _parse_timestamp_csv(get("timestamp"))

    logon_type_str = get("logon_type")
    logon_type = None
    if logon_type_str:
        try:
            logon_type = int(logon_type_str)
        except ValueError:
            pass

    return {
        "event_id":     event_id,
        "timestamp":    timestamp,
        "source":       get("source"),
        "computer":     get("computer").lower(),
        "user":         _clean_user(get("user")),
        "level":        get("level"),
        "message":      get("message"),
        "logon_type":   logon_type,
        "ip_address":   _clean_ip(get("ip_address")),
        "process_name": _clean_process(get("process_name")),
        "task_name":    get("task_name") or None,
        "service_name": get("service_name") or None,
        "raw":          dict(row),
    }

# ---------------------------------------------------------------------------
# JSON parser
# ---------------------------------------------------------------------------

def _parse_jsonl(path: Path) -> Iterator[dict]:
    """Parse a Windows Security Event JSONL file.

    Handles multiple formats:
        - Mixed channel datasets (filtered to Security channel by Channel field)
        - PowerShell Get-WinEvent JSON export
        - Azure Sentinel JSON export
        - Generic flat JSON with EventID field

    Security channel filter: processes events where Channel contains 'Security',
    or where no Channel field is present (generic/PowerShell format).
    """
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)

                    channel = obj.get(JSON_FIELD_ALIASES["channel"][0], "") or obj.get("channel", "")
                    # Skip non-Security channel events when Channel is present
                    if channel and "Security" not in channel:
                        continue
                    event = _parse_jsonl_record(obj)
                    if event:
                        yield event
                except json.JSONDecodeError as e:
                    logger.debug("Skipping malformed JSONL line %d: %s", line_num, e)
    except Exception as e:
        logger.error("Failed to read JSONL file %s: %s", path, e)
        raise


def _parse_jsonl_record(obj: dict) -> dict | None:
    """Normalise a flat JSON Windows Security event to our standard schema.

    Handles field name variations across mixed channel datasets, PowerShell and Sentinel exports.
    """
    def _get(*keys: str) -> str | None:
        for k in keys:
            v = obj.get(k)
            if v:
                return str(v)
        return None

    event_id_raw = _get(*JSON_FIELD_ALIASES["event_id"])
    if not event_id_raw:
        return None
    try:
        event_id = int(event_id_raw)
    except (ValueError, TypeError):
        return None

    # Timestamp
    ts_str = _get(*JSON_FIELD_ALIASES["timestamp"]) or ""
    timestamp = _parse_timestamp_jsonl(ts_str)
    user = _get(*JSON_FIELD_ALIASES["user"])
    ip = _get(*JSON_FIELD_ALIASES["ip_address"])
    logon_type_raw = _get(*JSON_FIELD_ALIASES["logon_type"])
    logon_type = None
    if logon_type_raw:
        try:
            logon_type = int(logon_type_raw)
        except (ValueError, TypeError):
            pass

    return {
        "event_id":     event_id,
        "timestamp":    timestamp,
        "source":       _get(*JSON_FIELD_ALIASES["source"]) or "",
        "computer":     (_get(*JSON_FIELD_ALIASES["computer"]) or "").lower(),
        "user":         _clean_user(user),
        "level":        obj.get("Severity", "INFO"),
        "message":      obj.get("Message", ""),
        "logon_type":   logon_type,
        "ip_address":   _clean_ip(ip),
        "process_name": _clean_process(_get(*JSON_FIELD_ALIASES["process_name"])),
        "task_name":    obj.get("TaskName"),
        "service_name": obj.get("ServiceName"),
        "raw":          obj,
    }

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_timestamp_evtx(ts: str) -> datetime:
    """Parse EVTX SystemTime string to UTC-aware datetime."""
    if not ts:
        return datetime.now(timezone.utc)
    ts = ts.rstrip("Z").split(".")[0]
    try:
        return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        try:
            return datetime.fromisoformat(ts).replace(tzinfo=timezone.utc)
        except ValueError:
            logger.debug("Could not parse EVTX timestamp: %s", ts)
            return datetime.now(timezone.utc)


def _parse_timestamp_csv(ts: str) -> datetime:
    """Parse CSV timestamp string to UTC-aware datetime.

    Handles common Windows Event Viewer export formats including
    US English, EU, ISO 8601 and German locale variants.
    """
    if not ts:
        return datetime.now(timezone.utc)

    formats = [
        "%m/%d/%Y %I:%M:%S %p",    # 01/15/2024 10:30:00 AM  (US)
        "%d/%m/%Y %H:%M:%S",        # 15/01/2024 10:30:00     (EU)
        "%Y-%m-%d %H:%M:%S",        # 2024-01-15 10:30:00     (ISO)
        "%Y-%m-%dT%H:%M:%S",        # 2024-01-15T10:30:00     (ISO 8601)
        "%m/%d/%Y %H:%M:%S",        # 01/15/2024 10:30:00     (US 24h)
        "%d.%m.%Y %H:%M:%S",        # 15.01.2024 10:30:00     (DE)
    ]
    for fmt in formats:
        try:
            return datetime.strptime(ts.strip(), fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue

    logger.debug("Could not parse CSV timestamp: %s", ts)
    return datetime.now(timezone.utc)


def _parse_timestamp_jsonl(ts: str) -> datetime:
    """Parse JSON event timestamp formats (ISO 8601 and datetime variants)."""
    if not ts:
        return datetime.now(timezone.utc)
    # Remove trailing Z and microseconds for simpler parsing
    ts = ts.rstrip("Z").split(".")[0].strip()
    formats = [
        "%Y-%m-%dT%H:%M:%S",   # 2020-08-07T14:32:25
        "%Y-%m-%d %H:%M:%S",   # 2020-08-07 14:32:25
    ]
    for fmt in formats:
        try:
            return datetime.strptime(ts, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    logger.debug("Could not parse JSONL timestamp: %s", ts)
    return datetime.now(timezone.utc)


def _clean_user(user: str | None) -> str | None:
    """Normalise username - strip domain prefix, filter system accounts."""
    if not user:
        return None
    if "\\" in user:
        user = user.split("\\")[-1]
    if "@" in user:
        user = user.split("@")[0]
    user = user.strip().lower()
    if user in ("", "-", "n/a", "system", "local service", "network service",
                "anonymous logon", "null sid"):
        return None
    return user


def _clean_ip(ip: str | None) -> str | None:
    """Normalise IP address - strip port, filter loopback and empty values."""
    if not ip:
        return None
    ip = ip.strip()
    if ip in ("", "-", "::1", "127.0.0.1", "n/a"):
        return None
    # Strip port if present (e.g. 192.168.1.1:4444)
    if ":" in ip and not ip.startswith("::"):
        parts = ip.rsplit(":", 1)
        if len(parts) == 2 and parts[1].isdigit():
            ip = parts[0]
    return ip or None


def _clean_process(process: str | None) -> str | None:
    """Normalise process name to lowercase basename."""
    if not process:
        return None
    process = process.strip().lower()
    if process in ("", "-", "n/a"):
        return None
    return Path(process).name or process


def _level_name(level_code: int) -> str:
    """Convert Windows event level integer to display name."""
    return {
        0: "LogAlways",
        1: "Critical",
        2: "Error",
        3: "Warning",
        4: "Information",
        5: "Verbose",
    }.get(level_code, "Unknown")
