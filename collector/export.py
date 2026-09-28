"""Export the public summary.json for the portfolio widget.

Usage:
    # own sensor: last 7 days, ending 24h ago
    python -m collector.export --sensor sensor-01 --out public/summary.json

    # public dataset: an explicit period, labelled with its source
    python -m collector.export --sensor dataset-cyberlab --dataset cyberlab \\
        --start 2019-05-18T00:00:00Z --end 2019-05-19T02:00:00Z --out public/summary.json

What leaves the private database (docs/threat-model.md, TB4):
- counts, time series and country totals only; never IPs, commands, URLs or payloads
- behaviour labels and ATT&CK ids from our own rules file, never attacker text
- passwords only if tried by at least --min-sources distinct sources, and only
  short printable-ASCII ones (filters out leaked real credentials)
- for our own sensor, data ends --delay-hours before --as-of (default 24h)
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1
SAFE_PASSWORD = re.compile(r"^[\x21-\x7e]{1,32}$")
HOURLY_UP_TO = timedelta(days=3)  # shorter periods get an hourly chart


def _utc(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _series(cur: Any, sensors: list[str], start: datetime, end: datetime) -> dict[str, Any]:
    unit = "hour" if end - start <= HOURLY_UP_TO else "day"
    step = timedelta(hours=1) if unit == "hour" else timedelta(days=1)
    first = start.replace(minute=0, second=0, microsecond=0)
    if unit == "day":
        first = first.replace(hour=0)
    cur.execute(f"""
        SELECT date_trunc('{unit}', first_seen_at AT TIME ZONE 'UTC') AS bucket, count(*)
        FROM sessions
        WHERE sensor_id = ANY(%(s)s) AND first_seen_at >= %(a)s AND first_seen_at < %(b)s
        GROUP BY 1""", {"s": sensors, "a": first, "b": end})
    counts = {b.replace(tzinfo=timezone.utc): n for b, n in cur.fetchall()}
    points, t = [], first
    while t < end:
        points.append({"t": _utc(t), "sessions": counts.get(t, 0)})
        t += step
    return {"unit": unit, "points": points}


def build_summary(cur: Any, sensors: list[str], start: datetime, end: datetime, *,
                  source: dict[str, Any], min_sources: int = 20, top: int = 6) -> dict[str, Any]:
    scope = "sensor_id = ANY(%(sensors)s) AND {ts} >= %(start)s AND {ts} < %(end)s"
    p = {"sensors": sensors, "start": start, "end": end}

    cur.execute(f"""
        SELECT count(*), count(DISTINCT src_ip_private), count(DISTINCT src_country)
        FROM sessions WHERE {scope.format(ts='first_seen_at')}""", p)
    sessions, sources, countries = cur.fetchone()
    cur.execute(f"SELECT count(*) FROM auth_attempts WHERE {scope.format(ts='ts')}", p)
    (logins,) = cur.fetchone()
    cur.execute(f"SELECT count(*) FROM commands WHERE {scope.format(ts='ts')}", p)
    (commands,) = cur.fetchone()

    cur.execute(f"""
        SELECT b.attack_technique, b.label, count(DISTINCT (b.sensor_id, b.session_id))
        FROM behavior_labels b
        JOIN sessions s USING (sensor_id, session_id)
        WHERE s.{scope.format(ts='first_seen_at')}
        GROUP BY 1, 2 ORDER BY 3 DESC, 1 LIMIT %(top)s""", {**p, "top": top})
    behaviours = [
        {"attack": attack, "label": label, "sessions": n,
         "share": round(n / sessions, 3) if sessions else 0}
        for attack, label, n in cur.fetchall()
    ]

    # What each session got to: the shape of the traffic, before any labels.
    cur.execute(f"""
        SELECT
          count(*) FILTER (WHERE NOT has_auth),
          count(*) FILTER (WHERE has_auth AND NOT s.login_success),
          count(*) FILTER (WHERE s.login_success AND NOT has_cmd),
          count(*) FILTER (WHERE s.login_success AND has_cmd)
        FROM (
          SELECT s.*,
                 EXISTS (SELECT 1 FROM auth_attempts a
                         WHERE a.sensor_id = s.sensor_id AND a.session_id = s.session_id) AS has_auth,
                 EXISTS (SELECT 1 FROM commands c
                         WHERE c.sensor_id = s.sensor_id AND c.session_id = s.session_id) AS has_cmd
          FROM sessions s WHERE s.{scope.format(ts='first_seen_at')}
        ) s""", p)
    no_login, failed_only, login_only, with_commands = cur.fetchone()
    outcomes = {
        "no_login_attempt": no_login,
        "login_failed": failed_only,
        "login_no_commands": login_only,
        "ran_commands": with_commands,
    }

    cur.execute(f"""
        SELECT src_country, count(*) FROM sessions
        WHERE {scope.format(ts='first_seen_at')} AND src_country IS NOT NULL
        GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT 5""", p)
    top_countries = [
        {"name": name, "share": round(n / sessions, 3) if sessions else 0}
        for name, n in cur.fetchall()
    ]

    cur.execute(f"""
        SELECT a.password_private, count(DISTINCT s.src_ip_private) AS sources
        FROM auth_attempts a JOIN sessions s USING (sensor_id, session_id)
        WHERE a.{scope.format(ts='ts')} AND a.password_private IS NOT NULL
        GROUP BY 1 HAVING count(DISTINCT s.src_ip_private) >= %(min)s
        ORDER BY 2 DESC, 1 LIMIT 50""", {**p, "min": min_sources})
    passwords = [pw for pw, _ in cur.fetchall() if SAFE_PASSWORD.match(pw)][:8]

    return {
        "schema": SCHEMA_VERSION,
        "generated_at": _utc(datetime.now(timezone.utc)),
        "source": source,
        "window": {"start": _utc(start), "end": _utc(end)},
        "totals": {
            "sessions": sessions,
            "login_attempts": logins,
            "unique_sources": sources,
            "commands": commands,
            "countries": countries or None,
        },
        "series": _series(cur, sensors, start, end),
        "outcomes": outcomes,
        "behaviours": behaviours,
        "top_countries": top_countries,
        "passwords": passwords,
        "password_min_sources": min_sources,
    }


def _parse_time(value: str) -> datetime:
    dt = datetime.fromisoformat(value)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def main(argv: list[str] | None = None) -> int:
    import psycopg

    from collector.datasets import DATASETS

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--sensor", action="append", required=True, help="sensor id(s) to include")
    ap.add_argument("--dataset", choices=sorted(DATASETS), help="label the output as this public dataset")
    ap.add_argument("--start", help="ISO start (with --end); default: rolling window")
    ap.add_argument("--end", help="ISO end (exclusive)")
    ap.add_argument("--as-of", help="ISO time to treat as 'now' for the rolling window")
    ap.add_argument("--window-days", type=int, default=7)
    ap.add_argument("--delay-hours", type=int, default=24)
    ap.add_argument("--min-sources", type=int, default=20)
    ap.add_argument("--sample", action="store_true", help="label the output as synthetic sample data")
    args = ap.parse_args(argv)

    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        print("DATABASE_URL is not set (see .env.example)", file=sys.stderr)
        return 2

    if args.start or args.end:
        if not (args.start and args.end):
            ap.error("--start and --end go together")
        start, end = _parse_time(args.start), _parse_time(args.end)
    else:
        now = _parse_time(args.as_of) if args.as_of else datetime.now(timezone.utc)
        end = (now - timedelta(hours=args.delay_hours)).replace(minute=0, second=0, microsecond=0)
        start = end - timedelta(days=args.window_days)
    if not start < end:
        ap.error("start must be before end")

    if args.dataset:
        ds = DATASETS[args.dataset]
        source = {"kind": "dataset", "name": ds.name, "url": ds.url, "license": ds.license}
    elif args.sample:
        source = {"kind": "sample", "name": "Synthetic sample data"}
    else:
        source = {"kind": "sensor", "name": "Own Cowrie sensor"}

    with psycopg.connect(dsn, connect_timeout=10) as conn, conn.cursor() as cur:
        summary = build_summary(cur, args.sensor, start, end, source=source,
                                min_sources=args.min_sources)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    tmp = args.out.with_suffix(".tmp")
    tmp.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    tmp.replace(args.out)
    t = summary["totals"]
    print(f"wrote {args.out}: {t['sessions']} sessions, {len(summary['behaviours'])} behaviours, "
          f"{len(summary['passwords'])} passwords, {len(summary['series']['points'])} "
          f"{summary['series']['unit']} points")
    return 0


if __name__ == "__main__":
    sys.exit(main())
