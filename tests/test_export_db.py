"""The public export must never leak private fields. Skipped unless DATABASE_URL is set."""
import json
import os
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from collector.classifier import classify, load_rules
from collector.parser import parse_lines
from collector.synthetic import generate

DSN = os.environ.get("DATABASE_URL")
pytestmark = pytest.mark.skipif(not DSN, reason="DATABASE_URL not set")


def test_export_contains_only_aggregates():
    psycopg = pytest.importorskip("psycopg")
    from collector.export import build_summary
    from collector.loader import load_events

    sensor = f"test-{uuid.uuid4().hex[:8]}"
    start = datetime(2026, 1, 1, tzinfo=timezone.utc)
    raw = list(generate(sessions=300, seed=21, start=start, mean_gap_s=1200))
    events, _ = parse_lines([json.dumps(e) for e in raw], sensor)
    rules = load_rules()

    with psycopg.connect(DSN) as conn:
        try:
            load_events(conn, events)
            with conn.cursor() as cur:
                # label sessions in-transaction, like collector.classifier does
                cur.execute(
                    "SELECT session_id FROM sessions WHERE sensor_id = %s", (sensor,))
                for (sid,) in cur.fetchall():
                    cmds = [e["input"] for e in raw
                            if e["session"] == sid and e["eventid"] == "cowrie.command.input"]
                    failed = sum(1 for e in raw
                                 if e["session"] == sid and e["eventid"] == "cowrie.login.failed")
                    for m in classify(cmds, failed, rules):
                        cur.execute(
                            "INSERT INTO behavior_labels (sensor_id, session_id, rule_id, label,"
                            " attack_technique, confidence) VALUES (%s,%s,%s,%s,%s,%s)",
                            (sensor, sid, m.rule.id, m.rule.label, m.rule.attack, m.rule.confidence))
                end = start + timedelta(days=5)
                summary = build_summary(cur, [sensor], start, end,
                                        source={"kind": "sample", "name": "test"})
        finally:
            conn.rollback()

    text = json.dumps(summary)
    private_values = (
        {e["src_ip"] for e in raw}
        | {e["url"] for e in raw if "url" in e}
        | {e["input"] for e in raw if "input" in e}
    )
    # skip very short commands like "w" that would match any text
    leaked = [v for v in private_values if len(v) >= 4 and v in text]
    assert leaked == []
    assert summary["totals"]["sessions"] > 0
    assert summary["series"]["unit"] == "day"
    assert len(summary["series"]["points"]) == 5
    assert sum(pt["sessions"] for pt in summary["series"]["points"]) == summary["totals"]["sessions"]
    assert summary["behaviours"], "expected some behaviour labels"
    assert all(0 <= b["share"] <= 1 for b in summary["behaviours"])
    assert sum(summary["outcomes"].values()) == summary["totals"]["sessions"]
    assert all(b["sessions"] <= summary["totals"]["sessions"] for b in summary["behaviours"])
