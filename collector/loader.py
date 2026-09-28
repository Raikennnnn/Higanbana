"""Load Cowrie JSON log files into PostgreSQL.

Usage:
    python -m collector.loader --sensor-id lab-01 var/cowrie/cowrie.json

The connection string comes from the DATABASE_URL environment variable.

Re-running on the same files is safe: raw_events has UNIQUE (sensor_id,
event_hash), and normalized rows are only written for events that were
newly inserted.
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import psycopg
from psycopg.types.json import Jsonb

from collector.parser import (
    AUTH_EVENTS,
    COMMAND_EVENTS,
    FILE_EVENTS,
    Event,
    dedupe,
    parse_lines,
    session_duration_s,
)

INSERT_RAW = """
INSERT INTO raw_events (sensor_id, event_hash, eventid, ts, session_id,
                        src_ip_private, payload_private)
VALUES (%s, %s, %s, %s, %s, %s, %s)
ON CONFLICT (sensor_id, event_hash) DO NOTHING
RETURNING id
"""

# Events can arrive in any order across files, so every field is merged
# rather than overwritten.
UPSERT_SESSION = """
INSERT INTO sessions (sensor_id, session_id, src_ip_private, src_country, src_port,
                      dst_port, protocol, client_version, first_seen_at, last_seen_at,
                      duration_s, login_success)
VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
ON CONFLICT (sensor_id, session_id) DO UPDATE SET
    src_ip_private = COALESCE(sessions.src_ip_private, EXCLUDED.src_ip_private),
    src_country    = COALESCE(sessions.src_country, EXCLUDED.src_country),
    src_port       = COALESCE(sessions.src_port, EXCLUDED.src_port),
    dst_port       = COALESCE(sessions.dst_port, EXCLUDED.dst_port),
    protocol       = COALESCE(sessions.protocol, EXCLUDED.protocol),
    client_version = COALESCE(sessions.client_version, EXCLUDED.client_version),
    first_seen_at  = LEAST(sessions.first_seen_at, EXCLUDED.first_seen_at),
    last_seen_at   = GREATEST(sessions.last_seen_at, EXCLUDED.last_seen_at),
    duration_s     = COALESCE(EXCLUDED.duration_s, sessions.duration_s),
    login_success  = sessions.login_success OR EXCLUDED.login_success
"""


def _int_or_none(value: object) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _str_or_none(value: object) -> str | None:
    return value if isinstance(value, str) else None


def _country_or_none(value: object) -> str | None:
    """Country name as provided by a dataset; "Unknown" and junk become None."""
    if not isinstance(value, str) or value == "Unknown" or not 1 < len(value) <= 60:
        return None
    return value


def _normalize(cur: psycopg.Cursor, raw_id: int, ev: Event) -> None:
    if ev.session_id is None:
        return
    p = ev.payload
    cur.execute(
        UPSERT_SESSION,
        (
            ev.sensor_id,
            ev.session_id,
            ev.src_ip,
            _country_or_none(p.get("country")),
            _int_or_none(p.get("src_port")),
            _int_or_none(p.get("dst_port")),
            _str_or_none(p.get("protocol")),
            _str_or_none(p.get("version")) if ev.eventid == "cowrie.client.version" else None,
            ev.ts,
            ev.ts,
            session_duration_s(p) if ev.eventid == "cowrie.session.closed" else None,
            ev.eventid == "cowrie.login.success",
        ),
    )

    if ev.eventid in AUTH_EVENTS:
        cur.execute(
            "INSERT INTO auth_attempts (raw_event_id, sensor_id, session_id, ts,"
            " username, password_private, success) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (raw_id, ev.sensor_id, ev.session_id, ev.ts,
             _str_or_none(p.get("username")), _str_or_none(p.get("password")),
             AUTH_EVENTS[ev.eventid]),
        )
    elif ev.eventid in COMMAND_EVENTS:
        cur.execute(
            "INSERT INTO commands (raw_event_id, sensor_id, session_id, ts, input_private)"
            " VALUES (%s, %s, %s, %s, %s)",
            (raw_id, ev.sensor_id, ev.session_id, ev.ts, _str_or_none(p.get("input")) or ""),
        )
    elif ev.eventid in FILE_EVENTS:
        cur.execute(
            "INSERT INTO file_events (raw_event_id, sensor_id, session_id, ts, kind,"
            " url_private, shasum, outfile) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
            (raw_id, ev.sensor_id, ev.session_id, ev.ts, FILE_EVENTS[ev.eventid],
             _str_or_none(p.get("url")), _str_or_none(p.get("shasum")),
             _str_or_none(p.get("outfile"))),
        )


def load_events(conn: psycopg.Connection, events: list[Event]) -> int:
    """Insert events; returns how many were new. Caller commits."""
    inserted = 0
    with conn.cursor() as cur:
        for sensor_id in {ev.sensor_id for ev in events}:
            cur.execute(
                "INSERT INTO sensors (sensor_id) VALUES (%s) ON CONFLICT DO NOTHING",
                (sensor_id,),
            )
        for ev in dedupe(events):
            cur.execute(
                INSERT_RAW,
                (ev.sensor_id, ev.event_hash, ev.eventid, ev.ts, ev.session_id,
                 ev.src_ip, Jsonb(ev.payload)),
            )
            row = cur.fetchone()
            if row is None:  # already loaded
                continue
            inserted += 1
            _normalize(cur, row[0], ev)
    return inserted


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--sensor-id", required=True)
    ap.add_argument("files", nargs="+", type=Path)
    args = ap.parse_args(argv)

    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        print("DATABASE_URL is not set (see .env.example)", file=sys.stderr)
        return 2

    with psycopg.connect(dsn, connect_timeout=10) as conn:
        for path in args.files:
            with path.open(encoding="utf-8", errors="replace") as fh:
                events, errors = parse_lines(fh, args.sensor_id)
            new = load_events(conn, events)
            conn.commit()
            print(f"{path}: {len(events)} parsed, {new} new, {len(errors)} bad lines")
            for lineno, reason in errors[:10]:
                print(f"  line {lineno}: {reason}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
