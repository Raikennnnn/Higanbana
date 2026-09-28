"""Build the live summary from SANS ISC DShield (the daily "live" layer).

Usage:
    python -m collector.dshield --out data/dshield/summary.json

Data: SANS Internet Storm Center / DShield, https://isc.sans.edu
License: CC BY-NC-SA 4.0. The summary this writes is derived from it and is
published under the same license. The API asks for a User-Agent with contact
details and for clients to back off on HTTP 429.

Only aggregates are used: daily SSH totals, the most attacked ports, and a
ranking of usernames seen by DShield's honeypots. No IP addresses are fetched.
Everything from the feed is validated; if anything looks wrong the script
fails without writing, so the last good summary stays published.

Standard library only, so it runs on a stock CI runner with no installs.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
from datetime import date, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

API = "https://isc.sans.edu/api"
USERNAMES_URL = "https://isc.sans.edu/sshallusernames.json"
USER_AGENT = "Higanbana/1.0 (+https://github.com/Raikennnnn/Higanbana; torreskennethraichen@gmail.com)"
SOURCE = {
    "name": "SANS Internet Storm Center (DShield)",
    "url": "https://isc.sans.edu",
    "license": "CC BY-NC-SA 4.0",
}

HISTORY_DAYS = 30
TOP_PORTS = 8
TOP_USERNAMES = 8
MIN_USERNAME_COUNT = 10_000  # skip rare, one-off strings
# Letters, digits and a few symbols common in real usernames. No markup,
# quotes, spaces or control characters: the feed is attacker-generated text.
SAFE_USERNAME = re.compile(r"^[A-Za-z0-9._@+=!#$%*-]{1,32}$")
ISO_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")

# Labels for ports that show up in the top list; anything else stays unnamed.
SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP",
    110: "POP3", 123: "NTP", 135: "MS RPC", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 853: "DNS over TLS", 1433: "MS SQL",
    1723: "PPTP", 2222: "SSH (alt)", 3306: "MySQL", 3389: "RDP",
    5060: "SIP", 5432: "PostgreSQL", 5555: "Android ADB", 5900: "VNC",
    6379: "Redis", 8000: "HTTP (alt)", 8080: "HTTP (alt)", 8443: "HTTPS (alt)",
    9200: "Elasticsearch", 23231: "Telnet (alt)", 37215: "Huawei router",
}


class FeedError(RuntimeError):
    pass


# ── fetching ──

def fetch_json(url: str, *, max_bytes: int, timeout: int = 60) -> Any:
    """GET a JSON document. One polite retry on 429, a hard size cap."""
    for attempt in (1, 2):
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as res:
                body = res.read(max_bytes + 1)
        except urllib.error.HTTPError as exc:
            if exc.code == 429 and attempt == 1:
                wait = exc.headers.get("Retry-After", "300")
                time.sleep(min(int(wait) if wait.isdigit() else 300, 600))
                continue
            raise FeedError(f"{url}: HTTP {exc.code}") from None
        except (urllib.error.URLError, TimeoutError) as exc:
            raise FeedError(f"{url}: {exc}") from None
        if len(body) > max_bytes:
            raise FeedError(f"{url}: response larger than {max_bytes} bytes")
        try:
            return json.loads(body)
        except json.JSONDecodeError:
            raise FeedError(f"{url}: not JSON") from None
    raise FeedError(f"{url}: still rate limited")


# ── validation helpers ──

def _count(v: Any) -> int | None:
    return v if isinstance(v, int) and not isinstance(v, bool) and 0 <= v < 10**12 else None


def _numbered(obj: Any) -> list[dict[str, Any]]:
    """DShield returns lists as {"0": {...}, "1": {...}, "date": ...}."""
    if not isinstance(obj, dict):
        raise FeedError("expected an object")
    return [obj[k] for k in sorted((k for k in obj if k.isdigit()), key=int) if isinstance(obj[k], dict)]


# ── building ──

def parse_port22(raw: Any) -> dict[str, Any]:
    data = raw.get("data") if isinstance(raw, dict) else None
    if not isinstance(data, dict) or not ISO_DATE.match(str(data.get("date", ""))):
        raise FeedError("port/22: missing data or date")
    out = {k: _count(data.get(k)) for k in ("records", "sources", "targets")}
    if None in out.values() or out["records"] == 0:
        raise FeedError("port/22: bad counts")
    return {"date": data["date"], "reports": out["records"], "sources": out["sources"], "targets": out["targets"]}


def parse_history(raw: Any) -> list[dict[str, Any]]:
    days = []
    for d in _numbered(raw):
        day, reports, sources = d.get("date"), _count(d.get("records")), _count(d.get("sources"))
        if isinstance(day, str) and ISO_DATE.match(day) and reports is not None and sources is not None:
            days.append({"date": day, "reports": reports, "sources": sources})
    days.sort(key=lambda d: d["date"])
    days = days[-HISTORY_DAYS:]
    if len(days) < 7:
        raise FeedError("porthistory: fewer than 7 valid days")
    return days


def parse_top_ports(raw: Any) -> list[dict[str, Any]]:
    ports = []
    for p in _numbered(raw):
        port, reports, sources = _count(p.get("targetport")), _count(p.get("records")), _count(p.get("sources"))
        if port is not None and 1 <= port <= 65535 and reports is not None and sources is not None:
            ports.append({"port": port, "service": SERVICES.get(port), "reports": reports, "sources": sources})
    ports.sort(key=lambda p: -p["reports"])
    if len(ports) < 3:
        raise FeedError("topports: fewer than 3 valid ports")
    return ports[:TOP_PORTS]


def parse_usernames(raw: Any, as_of: str) -> list[str]:
    """Top usernames seen in the last 30 days, ranked. Counts are dropped on
    purpose: DShield's counts are cumulative, so showing them as recent
    numbers would mislead."""
    if not isinstance(raw, list):
        raise FeedError("usernames: expected a list")
    cutoff = (date.fromisoformat(as_of) - timedelta(days=30)).isoformat()
    ok = []
    for u in raw:
        if not isinstance(u, dict):
            continue
        name, count, last = u.get("username"), _count(u.get("count")), u.get("lastseen")
        if (isinstance(name, str) and SAFE_USERNAME.match(name) and count is not None
                and count >= MIN_USERNAME_COUNT and isinstance(last, str) and last >= cutoff):
            ok.append((count, name))
    ok.sort(key=lambda t: (-t[0], t[1]))
    return [name for _, name in ok[:TOP_USERNAMES]]


def build_live_summary(port22: Any, history: Any, topports: Any, usernames: Any,
                       generated_at: datetime) -> dict[str, Any]:
    ssh = parse_port22(port22)
    ports = parse_top_ports(topports)
    rank = next((i + 1 for i, p in enumerate(ports) if p["port"] == 22), None)
    return {
        "schema": 1,
        "generated_at": generated_at.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
        "source": SOURCE,
        "date": ssh["date"],
        "ssh": {"reports": ssh["reports"], "sources": ssh["sources"], "targets": ssh["targets"], "rank": rank},
        "ssh_history": parse_history(history),
        "top_ports": ports,
        "top_usernames": parse_usernames(usernames, ssh["date"]),
    }


def fetch_live_summary() -> dict[str, Any]:
    port22 = fetch_json(f"{API}/port/22?json", max_bytes=64_000)
    day = parse_port22(port22)["date"]
    start = (date.fromisoformat(day) - timedelta(days=HISTORY_DAYS - 1)).isoformat()
    history = fetch_json(f"{API}/porthistory/22/{start}/{day}?json", max_bytes=256_000)
    topports = fetch_json(f"{API}/topports/records/20/{day}?json", max_bytes=64_000)
    usernames = fetch_json(USERNAMES_URL, max_bytes=50_000_000, timeout=120)
    return build_live_summary(port22, history, topports, usernames, datetime.now(timezone.utc))


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args(argv)
    try:
        summary = fetch_live_summary()
    except FeedError as exc:
        print(f"not updated: {exc}", file=sys.stderr)
        return 1
    args.out.parent.mkdir(parents=True, exist_ok=True)
    tmp = args.out.with_suffix(".tmp")
    tmp.write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    tmp.replace(args.out)
    print(f"wrote {args.out}: {summary['date']}, {summary['ssh']['reports']:,} SSH reports, "
          f"{len(summary['top_ports'])} ports, {len(summary['top_usernames'])} usernames")
    return 0


if __name__ == "__main__":
    sys.exit(main())
