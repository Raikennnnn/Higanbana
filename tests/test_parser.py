import json

import pytest

from collector.parser import (
    MAX_LINE_BYTES,
    ParseError,
    event_hash,
    parse_line,
    parse_lines,
    session_duration_s,
)

LOGIN = {
    "eventid": "cowrie.login.failed",
    "timestamp": "2026-01-01T00:00:01.123456Z",
    "session": "a1b2c3d4e5f6",
    "src_ip": "192.0.2.10",
    "username": "root",
    "password": "123456",
}


def test_parses_valid_event():
    ev = parse_line(json.dumps(LOGIN), "lab-01")
    assert ev is not None
    assert ev.eventid == "cowrie.login.failed"
    assert ev.session_id == "a1b2c3d4e5f6"
    assert ev.src_ip == "192.0.2.10"
    assert ev.ts.utcoffset().total_seconds() == 0
    assert ev.sensor_id == "lab-01"


def test_blank_line_is_skipped():
    assert parse_line("   \n", "lab-01") is None


@pytest.mark.parametrize(
    "line, reason",
    [
        ("{not json", "invalid JSON"),
        ("[1, 2]", "not a JSON object"),
        (json.dumps({"timestamp": LOGIN["timestamp"]}), "missing eventid"),
        (json.dumps({"eventid": "x"}), "timestamp"),
        (json.dumps({"eventid": "x", "timestamp": "2026-01-01T00:00:00"}), "no timezone"),
    ],
)
def test_rejects_bad_lines(line, reason):
    with pytest.raises(ParseError, match=reason):
        parse_line(line, "lab-01")


def test_rejects_oversized_line():
    big = dict(LOGIN, password="x" * MAX_LINE_BYTES)
    with pytest.raises(ParseError, match="exceeds"):
        parse_line(json.dumps(big), "lab-01")


def test_bad_lines_are_collected_not_raised():
    lines = [json.dumps(LOGIN), "garbage", "", json.dumps(dict(LOGIN, username="admin"))]
    events, errors = parse_lines(lines, "lab-01")
    assert len(events) == 2
    assert [lineno for lineno, _ in errors] == [2]


def test_hash_ignores_key_order():
    reordered = dict(reversed(list(LOGIN.items())))
    assert event_hash(LOGIN) == event_hash(reordered)


def test_hash_changes_with_content():
    assert event_hash(LOGIN) != event_hash(dict(LOGIN, password="1234567"))


@pytest.mark.parametrize(
    "payload, expected",
    [
        ({"duration_ms": 215}, 0.215),  # Cowrie 3.x
        ({"duration": 4.5}, 4.5),  # older Cowrie
        ({"duration": "12.25"}, 12.25),
        ({"duration": "abc"}, None),
        ({"duration_ms": True}, None),
        ({}, None),
    ],
)
def test_session_duration(payload, expected):
    assert session_duration_s(payload) == expected


def test_attacker_controlled_types_do_not_crash():
    ev = parse_line(json.dumps(dict(LOGIN, session=123, src_ip=["x"])), "lab-01")
    assert ev.session_id is None
    assert ev.src_ip is None
