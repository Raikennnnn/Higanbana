"""Parse Cowrie JSON log lines into normalized events.

Pure functions only (no database access), so this module is easy to test.
Every field in a Cowrie log is attacker-influenced: treat it as untrusted
data, never as code or markup.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Iterable

# Lines longer than this are rejected rather than parsed. Cowrie lines are
# normally well under 4 KiB; this guards against a tampered log file.
MAX_LINE_BYTES = 64 * 1024

# Cowrie eventids that get their own normalized table. Everything else is
# still stored in raw_events.
AUTH_EVENTS = {"cowrie.login.success": True, "cowrie.login.failed": False}
COMMAND_EVENTS = {"cowrie.command.input"}
FILE_EVENTS = {
    "cowrie.session.file_download": "download",
    "cowrie.session.file_download.failed": "download_failed",
    "cowrie.session.file_upload": "upload",
}


class ParseError(ValueError):
    pass


@dataclass(frozen=True)
class Event:
    sensor_id: str
    event_hash: str
    eventid: str
    ts: datetime
    session_id: str | None
    src_ip: str | None
    payload: dict[str, Any]

    @property
    def dedup_key(self) -> tuple[str, str]:
        return (self.sensor_id, self.event_hash)


def event_hash(obj: dict[str, Any]) -> str:
    """SHA-256 of the event's canonical JSON form (key order doesn't matter)."""
    canonical = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def session_duration_s(payload: dict[str, Any]) -> float | None:
    """Duration of a closed session in seconds.

    Cowrie 3.x logs `duration_ms` (int); older versions log `duration`
    (seconds, sometimes as a string). Anything else counts as unknown.
    """
    ms = payload.get("duration_ms")
    if isinstance(ms, (int, float)) and not isinstance(ms, bool):
        return ms / 1000
    secs = payload.get("duration")
    if isinstance(secs, bool):
        return None
    if isinstance(secs, (int, float)):
        return float(secs)
    if isinstance(secs, str):
        try:
            return float(secs)
        except ValueError:
            return None
    return None


def parse_line(line: str, sensor_id: str) -> Event | None:
    """Parse one Cowrie JSON line. Returns None for blank lines."""
    if not line.strip():
        return None
    if len(line.encode("utf-8")) > MAX_LINE_BYTES:
        raise ParseError(f"line exceeds {MAX_LINE_BYTES} bytes")
    try:
        obj = json.loads(line)
    except json.JSONDecodeError as exc:
        raise ParseError(f"invalid JSON: {exc.msg}") from None
    if not isinstance(obj, dict):
        raise ParseError("event is not a JSON object")

    eventid = obj.get("eventid")
    if not isinstance(eventid, str) or not eventid:
        raise ParseError("missing eventid")
    try:
        ts = datetime.fromisoformat(obj["timestamp"])
    except (KeyError, TypeError, ValueError):
        raise ParseError("missing or invalid timestamp") from None
    if ts.tzinfo is None:
        raise ParseError("timestamp has no timezone")

    session_id = obj.get("session")
    src_ip = obj.get("src_ip")
    return Event(
        sensor_id=sensor_id,
        event_hash=event_hash(obj),
        eventid=eventid,
        ts=ts,
        session_id=session_id if isinstance(session_id, str) else None,
        src_ip=src_ip if isinstance(src_ip, str) else None,
        payload=obj,
    )


def parse_lines(
    lines: Iterable[str], sensor_id: str
) -> tuple[list[Event], list[tuple[int, str]]]:
    """Parse many lines. Bad lines are collected as (line_number, reason), not raised."""
    events: list[Event] = []
    errors: list[tuple[int, str]] = []
    for lineno, line in enumerate(lines, start=1):
        try:
            event = parse_line(line, sensor_id)
        except ParseError as exc:
            errors.append((lineno, str(exc)))
            continue
        if event is not None:
            events.append(event)
    return events, errors


def dedupe(events: Iterable[Event]) -> list[Event]:
    """Drop repeated events within a batch, keeping first occurrence order.

    The database's UNIQUE (sensor_id, event_hash) constraint is the real
    guarantee across batches; this just avoids pointless round trips.
    """
    seen: set[tuple[str, str]] = set()
    unique: list[Event] = []
    for event in events:
        if event.dedup_key in seen:
            continue
        seen.add(event.dedup_key)
        unique.append(event)
    return unique
