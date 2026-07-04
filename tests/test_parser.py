"""Tests for src.parser - CSV/JSONL/EVTX-XML parsing and normalisation."""
from __future__ import annotations

import json

import pytest

from src.parser import (
    _build_column_map,
    _clean_ip,
    _clean_process,
    _clean_user,
    _level_name,
    _parse_evtx_record_xml,
    _parse_timestamp_csv,
    _parse_timestamp_evtx,
    _parse_timestamp_jsonl,
    parse,
    parse_many,
)

# ---------------------------------------------------------------------------
# parse() dispatch
# ---------------------------------------------------------------------------


def test_parse_csv_file(sample_csv_path):
    events = parse(sample_csv_path)
    assert len(events) == 3
    assert [e["event_id"] for e in events] == [4624, 4625, 1102]
    # sorted ascending by timestamp
    assert events[0]["timestamp"] <= events[-1]["timestamp"]
    assert events[0]["user"] == "jsmith"
    assert events[0]["computer"] == "ws01.corp.local"
    assert events[0]["logon_type"] == 3
    assert events[0]["ip_address"] == "10.0.0.15"


def test_parse_jsonl_file(sample_jsonl_path):
    events = parse(sample_jsonl_path)
    assert len(events) == 2
    assert events[0]["event_id"] == 4624
    assert events[0]["computer"] == "ws01.corp.local"
    assert events[1]["event_id"] == 1102


def test_parse_unsupported_extension(tmp_path):
    bad = tmp_path / "log.txt"
    bad.write_text("hello")
    with pytest.raises(ValueError, match="Unsupported file type"):
        parse(bad)


def test_parse_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        parse(tmp_path / "nope.csv")


def test_parse_many_skips_bad_paths(sample_csv_path, tmp_path):
    events = parse_many([sample_csv_path, tmp_path / "missing.csv"])
    assert len(events) == 3


# ---------------------------------------------------------------------------
# CSV specifics
# ---------------------------------------------------------------------------


def test_csv_row_with_bad_event_id_skipped(tmp_path):
    path = tmp_path / "bad.csv"
    path.write_text(
        "Event ID,Date and Time,Computer\n"
        "abc,01/15/2026 09:00:00,ws01\n"
        "4624,01/15/2026 09:00:01,ws01\n"
    )
    events = parse(path)
    assert len(events) == 1
    assert events[0]["event_id"] == 4624


def test_csv_row_with_unparseable_timestamp_skipped(tmp_path):
    path = tmp_path / "badts.csv"
    path.write_text(
        "Event ID,Date and Time,Computer\n"
        "4624,not-a-date,ws01\n"
        "4624,01/15/2026 09:00:01,ws01\n"
    )
    events = parse(path)
    assert len(events) == 1


def test_build_column_map_is_case_insensitive():
    col_map = _build_column_map(["EVENT id", "TimeCreated", "computer"])
    assert col_map["event_id"] == "EVENT id"
    assert col_map["timestamp"] == "TimeCreated"
    assert col_map["computer"] == "computer"


# ---------------------------------------------------------------------------
# JSONL specifics
# ---------------------------------------------------------------------------


def test_jsonl_channel_filter(tmp_path):
    path = tmp_path / "mixed.json"
    records = [
        {"EventID": 4624, "EventTime": "2026-01-15 09:00:00",
         "Channel": "Security", "Hostname": "ws01"},
        {"EventID": 1, "EventTime": "2026-01-15 09:00:01",
         "Channel": "Microsoft-Windows-Sysmon/Operational", "Hostname": "ws01"},
        {"EventID": 1000, "EventTime": "2026-01-15 09:00:02",
         "Channel": "Application", "Hostname": "ws01"},
    ]
    path.write_text("\n".join(json.dumps(r) for r in records))
    events = parse(path)
    assert [e["event_id"] for e in events] == [4624, 1]


def test_jsonl_malformed_lines_and_missing_timestamp_skipped(tmp_path):
    path = tmp_path / "broken.json"
    path.write_text(
        "{not json}\n"
        '{"EventID": 4624, "Channel": "Security"}\n'
        '{"EventID": 4624, "EventTime": "2026-01-15 09:00:00", "Channel": "Security"}\n'
    )
    events = parse(path)
    assert len(events) == 1


# ---------------------------------------------------------------------------
# EVTX record XML
# ---------------------------------------------------------------------------

_EVTX_XML = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="Microsoft-Windows-Security-Auditing"/>
    <EventID>4625</EventID>
    <Level>0</Level>
    <TimeCreated SystemTime="2026-01-15T09:00:00.123456Z"/>
    <Computer>WS01.corp.local</Computer>
  </System>
  <EventData>
    <Data Name="TargetUserName">CORP\\admin</Data>
    <Data Name="IpAddress">185.220.101.1</Data>
    <Data Name="LogonType">3</Data>
  </EventData>
</Event>"""


def test_parse_evtx_record_xml():
    event = _parse_evtx_record_xml(_EVTX_XML)
    assert event is not None
    assert event["event_id"] == 4625
    assert event["computer"] == "ws01.corp.local"
    assert event["user"] == "admin"          # domain prefix stripped
    assert event["ip_address"] == "185.220.101.1"
    assert event["logon_type"] == 3
    assert event["timestamp"].year == 2026
    assert event["raw"]["LogonType"] == "3"


def test_parse_evtx_record_xml_without_system_returns_none():
    xml = '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"/>'
    assert _parse_evtx_record_xml(xml) is None


def test_parse_evtx_record_invalid_xml_returns_none():
    assert _parse_evtx_record_xml("<not-closed") is None


# ---------------------------------------------------------------------------
# Timestamp parsing
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("ts", [
    "01/15/2026 09:30:00 AM",   # US 12h
    "2026-01-15 09:30:00",      # ISO
    "2026-01-15T09:30:00",      # ISO 8601
    "15.01.2026 09:30:00",      # DE
])
def test_parse_timestamp_csv_formats(ts):
    parsed = _parse_timestamp_csv(ts)
    assert parsed is not None
    assert parsed.tzinfo is not None
    assert (parsed.year, parsed.minute) == (2026, 30)


def test_parse_timestamp_csv_unparseable_returns_none():
    assert _parse_timestamp_csv("not a date") is None
    assert _parse_timestamp_csv("") is None


def test_parse_timestamp_evtx():
    parsed = _parse_timestamp_evtx("2026-01-15T09:00:00.123456Z")
    assert parsed is not None and parsed.hour == 9
    assert _parse_timestamp_evtx("") is None
    assert _parse_timestamp_evtx("garbage") is None


def test_parse_timestamp_jsonl():
    assert _parse_timestamp_jsonl("2026-01-15T09:00:00Z") is not None
    assert _parse_timestamp_jsonl("2026-01-15 09:00:00") is not None
    assert _parse_timestamp_jsonl("") is None
    assert _parse_timestamp_jsonl("garbage") is None


# ---------------------------------------------------------------------------
# Field cleaners
# ---------------------------------------------------------------------------


def test_clean_user():
    assert _clean_user("CORP\\JSmith") == "jsmith"
    assert _clean_user("jsmith@corp.local") == "jsmith"
    assert _clean_user("SYSTEM") is None
    assert _clean_user("-") is None
    assert _clean_user(None) is None


def test_clean_ip():
    assert _clean_ip("192.168.1.1:4444") == "192.168.1.1"
    assert _clean_ip("10.0.0.1") == "10.0.0.1"
    assert _clean_ip("fe80::1") == "fe80::1"     # IPv6 left intact
    assert _clean_ip("::1") is None
    assert _clean_ip("127.0.0.1") is None
    assert _clean_ip("-") is None
    assert _clean_ip(None) is None


def test_clean_process():
    assert _clean_process("C:\\Windows\\System32\\cmd.exe") == "cmd.exe"
    assert _clean_process("POWERSHELL.EXE") == "powershell.exe"
    assert _clean_process("-") is None
    assert _clean_process(None) is None


def test_level_name():
    assert _level_name(2) == "Error"
    assert _level_name(4) == "Information"
    assert _level_name(99) == "Unknown"
