"""Import public honeypot datasets through the normal pipeline.

Usage:
    python -m collector.datasets cyberlab sample-data/cyberlab-2019-05-18.jsonl

Supported:
  cyberlab  CyberLab honeynet dataset (about 50 Cowrie honeypots, 2019).
            Sedlar, U., Kren, M., Stefanic Juznic, L., Volk, M. (2020).
            "CyberLab honeynet dataset". Zenodo. https://doi.org/10.5281/zenodo.3687527
            License: CC BY 4.0. IPs are pseudonymised (hashed) by the authors.
            Input: the flattened JSON-lines day file produced by
            https://github.com/b33pl0g1c/honeypot-log-analyzer (src/prepare_dataset.py).
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Iterator

# Cowrie 2019 logged commands as success/failed; current Cowrie logs every
# command as cowrie.command.input. Normalising here keeps the pipeline on one
# event vocabulary.
LEGACY_COMMAND_EVENTS = {"cowrie.command.success", "cowrie.command.failed"}


@dataclass(frozen=True)
class Dataset:
    key: str
    sensor_id: str
    name: str
    url: str
    license: str
    adapt: Callable[[dict[str, Any]], dict[str, Any] | None]


def adapt_cyberlab(ev: dict[str, Any]) -> dict[str, Any] | None:
    out = dict(ev)
    if ev.get("eventid") in LEGACY_COMMAND_EVENTS:
        out["legacy_eventid"] = ev["eventid"]
        out["eventid"] = "cowrie.command.input"
    return out


DATASETS = {
    "cyberlab": Dataset(
        key="cyberlab",
        sensor_id="dataset-cyberlab",
        name="CyberLab honeynet dataset",
        url="https://doi.org/10.5281/zenodo.3687527",
        license="CC BY 4.0",
        adapt=adapt_cyberlab,
    ),
}


def adapted_lines(lines: Iterable[str], dataset: Dataset) -> Iterator[str]:
    """Yield Cowrie-shaped JSON lines. Unparseable lines pass through unchanged
    so the normal parser reports them as bad lines."""
    for line in lines:
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            yield line
            continue
        if not isinstance(ev, dict):
            yield line
            continue
        out = dataset.adapt(ev)
        if out is not None:
            yield json.dumps(out, ensure_ascii=False)


def main(argv: list[str] | None = None) -> int:
    import psycopg

    from collector.loader import load_events
    from collector.parser import parse_lines

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("dataset", choices=sorted(DATASETS))
    ap.add_argument("files", nargs="+", type=Path)
    args = ap.parse_args(argv)

    dsn = os.environ.get("DATABASE_URL")
    if not dsn:
        print("DATABASE_URL is not set (see .env.example)", file=sys.stderr)
        return 2
    ds = DATASETS[args.dataset]

    with psycopg.connect(dsn, connect_timeout=10) as conn:
        with conn.cursor() as cur:
            cur.execute(
                "INSERT INTO sensors (sensor_id, provider, notes) VALUES (%s, 'dataset', %s)"
                " ON CONFLICT (sensor_id) DO UPDATE SET provider = 'dataset', notes = EXCLUDED.notes",
                (ds.sensor_id, f"{ds.name} ({ds.license}) {ds.url}"),
            )
        for path in args.files:
            with path.open(encoding="utf-8", errors="replace") as fh:
                events, errors = parse_lines(adapted_lines(fh, ds), ds.sensor_id)
            new = load_events(conn, events)
            conn.commit()
            print(f"{path}: {len(events)} parsed, {new} new, {len(errors)} bad lines")
    return 0


if __name__ == "__main__":
    sys.exit(main())
