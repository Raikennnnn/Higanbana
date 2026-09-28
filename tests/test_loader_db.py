"""Integration test against a real PostgreSQL. Skipped unless DATABASE_URL is set.

Run with the Docker lab up:
    docker compose up -d postgres
    $env:DATABASE_URL = "postgresql://honeypot:<password>@127.0.0.1:5432/honeypot"
    pytest tests/test_loader_db.py
"""
import json
import os
import uuid
from datetime import datetime, timezone

import pytest

from collector.parser import parse_lines
from collector.synthetic import generate

DSN = os.environ.get("DATABASE_URL")
pytestmark = pytest.mark.skipif(not DSN, reason="DATABASE_URL not set")


def test_loading_twice_inserts_nothing_new():
    psycopg = pytest.importorskip("psycopg")
    from collector.loader import load_events

    sensor = f"test-{uuid.uuid4().hex[:8]}"
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    lines = [json.dumps(ev) for ev in generate(sessions=30, seed=9, start=start, duplicate_rate=0.2)]
    events, errors = parse_lines(lines, sensor)
    assert not errors

    with psycopg.connect(DSN) as conn:
        try:
            first = load_events(conn, events)
            second = load_events(conn, events)
            with conn.cursor() as cur:
                cur.execute("SELECT count(*) FROM raw_events WHERE sensor_id = %s", (sensor,))
                raw = cur.fetchone()[0]
                cur.execute(
                    "SELECT count(*), count(duration_s) FROM sessions WHERE sensor_id = %s",
                    (sensor,),
                )
                sessions, with_duration = cur.fetchone()
        finally:
            conn.rollback()  # leave the database untouched

    assert first == raw == len({e.event_hash for e in events})
    assert second == 0
    assert sessions == with_duration == 30
