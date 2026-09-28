import json
from datetime import datetime, timezone

from collector.parser import dedupe, parse_lines
from collector.synthetic import generate

START = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _lines(**kwargs):
    return [json.dumps(ev) for ev in generate(start=START, **kwargs)]


def test_duplicates_are_removed():
    clean, _ = parse_lines(_lines(sessions=50, seed=1), "lab-01")
    noisy, _ = parse_lines(_lines(sessions=50, seed=1, duplicate_rate=0.3), "lab-01")
    assert len(noisy) > len(clean)
    assert [e.event_hash for e in dedupe(noisy)] == [e.event_hash for e in clean]


def test_same_event_on_two_sensors_is_kept_twice():
    lines = _lines(sessions=5, seed=2)
    a, _ = parse_lines(lines, "sensor-a")
    b, _ = parse_lines(lines, "sensor-b")
    assert len(dedupe(a + b)) == len(a) * 2


def test_dedupe_is_idempotent():
    events, _ = parse_lines(_lines(sessions=20, seed=3, duplicate_rate=0.5), "lab-01")
    once = dedupe(events)
    assert dedupe(once) == once


def test_no_hash_collisions_in_clean_data():
    events, _ = parse_lines(_lines(sessions=500, seed=4), "lab-01")
    assert len({e.event_hash for e in events}) == len(events)
