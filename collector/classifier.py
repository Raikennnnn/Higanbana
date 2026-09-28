"""Label sessions with behaviours using rules/command-classification.yml.

Usage:
    python -m collector.classifier            # (re)label every session

Idempotent: labels are unique per (sensor_id, session_id, rule_id).
"""
from __future__ import annotations

import argparse
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

import yaml

DEFAULT_RULES = Path(__file__).resolve().parent.parent / "rules" / "command-classification.yml"
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
CONFIDENCE = {"low", "medium", "high"}


@dataclass(frozen=True)
class Rule:
    id: str
    label: str
    attack: str | None
    confidence: str
    kind: str
    pattern: re.Pattern[str] | None
    minimum: int
    eventid: str | None
    evidence: str


@dataclass(frozen=True)
class Match:
    rule: Rule
    evidence: str  # the command or count that triggered it (private data)


def load_rules(path: Path = DEFAULT_RULES) -> list[Rule]:
    """Load and validate rules. Raises ValueError on any malformed rule."""
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(doc, dict) or doc.get("version") != 1:
        raise ValueError("rules file must have version: 1")
    rules: list[Rule] = []
    seen: set[str] = set()
    for raw in doc.get("rules", []):
        rid = raw.get("id")
        if not rid or rid in seen:
            raise ValueError(f"missing or duplicate rule id: {rid!r}")
        seen.add(rid)
        attack = raw.get("attack")
        if attack is not None and not TECHNIQUE_RE.match(attack):
            raise ValueError(f"{rid}: bad ATT&CK id {attack!r}")
        if raw.get("confidence") not in CONFIDENCE:
            raise ValueError(f"{rid}: confidence must be one of {sorted(CONFIDENCE)}")
        for field in ("label", "evidence"):
            if not raw.get(field):
                raise ValueError(f"{rid}: missing {field}")
        match = raw.get("match") or {}
        kind = match.get("type")
        pattern, minimum, eventid = None, 0, None
        if kind == "command":
            pattern = re.compile(match["regex"])
        elif kind == "failed_logins":
            minimum = int(match["min"])
        elif kind == "event":
            eventid, minimum = str(match["eventid"]), int(match.get("min", 1))
            if not eventid.startswith("cowrie."):
                raise ValueError(f"{rid}: eventid must be a cowrie.* event")
        else:
            raise ValueError(f"{rid}: unknown match type {kind!r}")
        rules.append(Rule(rid, raw["label"], attack, raw["confidence"], kind,
                          pattern, minimum, eventid, raw["evidence"]))
    return rules


def classify(commands: Iterable[str], failed_logins: int, rules: list[Rule],
             event_counts: dict[str, int] | None = None) -> list[Match]:
    """Return one match per rule that fires for this session (first evidence wins)."""
    commands = list(commands)
    event_counts = event_counts or {}
    matches: list[Match] = []
    for rule in rules:
        if rule.kind == "failed_logins":
            if failed_logins >= rule.minimum:
                matches.append(Match(rule, f"{failed_logins} failed logins"))
        elif rule.kind == "event":
            n = event_counts.get(rule.eventid, 0)
            if n >= rule.minimum:
                matches.append(Match(rule, f"{n} x {rule.eventid}"))
        else:
            hit = next((c for c in commands if rule.pattern.search(c)), None)
            if hit is not None:
                matches.append(Match(rule, hit))
    return matches


SESSIONS_SQL = """
SELECT s.sensor_id, s.session_id,
       COALESCE((SELECT array_agg(c.input_private ORDER BY c.ts) FROM commands c
                 WHERE c.sensor_id = s.sensor_id AND c.session_id = s.session_id), '{}'),
       (SELECT count(*) FROM auth_attempts a
        WHERE a.sensor_id = s.sensor_id AND a.session_id = s.session_id AND NOT a.success),
       COALESCE((SELECT jsonb_object_agg(eventid, n) FROM
                   (SELECT eventid, count(*) AS n FROM raw_events r
                    WHERE r.sensor_id = s.sensor_id AND r.session_id = s.session_id
                    GROUP BY eventid) e), '{}'::jsonb)
FROM sessions s
"""

INSERT_LABEL = """
INSERT INTO behavior_labels (sensor_id, session_id, rule_id, label, attack_technique,
                             confidence, evidence_private)
VALUES (%s, %s, %s, %s, %s, %s, %s)
ON CONFLICT (sensor_id, session_id, rule_id) DO NOTHING
"""


def main(argv: list[str] | None = None) -> int:
    import psycopg

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--rules", type=Path, default=DEFAULT_RULES)
    args = ap.parse_args(argv)

    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        print("DATABASE_URL is not set (see .env.example)", file=sys.stderr)
        return 2
    rules = load_rules(args.rules)

    sessions = labelled = 0
    with psycopg.connect(dsn, connect_timeout=10) as conn, conn.cursor() as cur:
        rows = cur.execute(SESSIONS_SQL).fetchall()
        for sensor_id, session_id, commands, failed, event_counts in rows:
            sessions += 1
            matches = classify(commands, failed, rules, event_counts)
            labelled += bool(matches)
            cur.executemany(INSERT_LABEL, [
                (sensor_id, session_id, m.rule.id, m.rule.label, m.rule.attack,
                 m.rule.confidence, m.evidence) for m in matches
            ])
        conn.commit()
    print(f"{sessions} sessions checked, {labelled} with at least one label")
    return 0


if __name__ == "__main__":
    sys.exit(main())
