"""DShield feed parsing, using small hand-made responses shaped like the real API."""
import json
from datetime import datetime, timezone

import pytest

from collector.dshield import FeedError, build_live_summary, parse_history, parse_usernames

NOW = datetime(2026, 9, 29, 6, 17, tzinfo=timezone.utc)
PORT22 = {"number": 22, "data": {"date": "2026-09-28", "records": 902671, "targets": 287, "sources": 15840}}
HISTORY = {str(i): {"date": f"2026-09-{i + 1:02d}", "records": 1_000_000 + i, "sources": 25_000 + i}
           for i in range(28)}
TOPPORTS = {
    "0": {"rank": 1, "targetport": 22, "records": 902671, "targets": 287, "sources": 15840},
    "1": {"rank": 2, "targetport": 8080, "records": 872576, "targets": 273, "sources": 9514},
    "2": {"rank": 3, "targetport": 443, "records": 866629, "targets": 315, "sources": 9427},
    "3": {"rank": 4, "targetport": 16881, "records": 148178, "targets": 16, "sources": 817},
    "date": "2026-09-28", "limit": 4,
}
USERNAMES = [
    {"username": "root", "count": 1_913_184_545, "firstseen": "2020-01-01", "lastseen": "2026-09-29"},
    {"username": "admin", "count": 758_963_640, "firstseen": "2020-01-01", "lastseen": "2026-09-29"},
    {"username": "\u0000\f\u0000", "count": 965, "firstseen": "2026-04-30", "lastseen": "2026-09-28"},
    {"username": "<action>MSMQ:poc</action>", "count": 5_000_000, "firstseen": "2026-06-30", "lastseen": "2026-09-20"},
    {"username": "x" * 40, "count": 9_000_000, "firstseen": "2026-01-01", "lastseen": "2026-09-28"},
    {"username": "rare1", "count": 12, "firstseen": "2026-09-01", "lastseen": "2026-09-28"},
    {"username": "oldname", "count": 99_000_000, "firstseen": "2019-01-01", "lastseen": "2026-07-01"},
]


def build():
    return build_live_summary(PORT22, HISTORY, TOPPORTS, USERNAMES, NOW)


def test_builds_expected_shape():
    s = build()
    assert s["date"] == "2026-09-28"
    assert s["ssh"] == {"reports": 902671, "sources": 15840, "targets": 287, "rank": 1}
    assert [p["port"] for p in s["top_ports"]] == [22, 8080, 443, 16881]
    assert s["top_ports"][0]["service"] == "SSH"
    assert s["top_ports"][3]["service"] is None  # unknown ports stay unnamed
    assert s["source"]["license"] == "CC BY-NC-SA 4.0"
    assert s["generated_at"] == "2026-09-29T06:17:00Z"


def test_usernames_are_filtered_and_ranked_without_counts():
    s = build()
    # control characters, markup, oversized, rare and stale entries are all dropped
    assert s["top_usernames"] == ["root", "admin"]
    assert "count" not in json.dumps(s["top_usernames"])


def test_history_sorted_and_capped():
    shuffled = dict(reversed(list(HISTORY.items())))
    days = parse_history(shuffled)
    assert [d["date"] for d in days] == sorted(d["date"] for d in days)
    many = {str(i): {"date": f"2026-{8 + i // 30:02d}-{i % 30 + 1:02d}", "records": 1, "sources": 1} for i in range(45)}
    assert len(parse_history(many)) == 30


def test_no_ip_addresses_in_output():
    import re
    assert not re.search(r"\b\d{1,3}(\.\d{1,3}){3}\b", json.dumps(build()))


@pytest.mark.parametrize(
    "port22, history, topports, usernames",
    [
        ({"data": {}}, HISTORY, TOPPORTS, USERNAMES),  # no date
        ({"data": {**PORT22["data"], "records": 0}}, HISTORY, TOPPORTS, USERNAMES),  # empty day
        ({"data": {**PORT22["data"], "records": "902671"}}, HISTORY, TOPPORTS, USERNAMES),  # string count
        (PORT22, {"0": {"date": "2026-09-01", "records": 1, "sources": 1}}, TOPPORTS, USERNAMES),  # too little history
        (PORT22, HISTORY, {"0": {"targetport": 99999, "records": 1, "sources": 1}}, USERNAMES),  # bad ports
        (PORT22, HISTORY, TOPPORTS, {"not": "a list"}),
        ("<html>maintenance</html>", HISTORY, TOPPORTS, USERNAMES),
    ],
)
def test_bad_feed_raises_instead_of_writing(port22, history, topports, usernames):
    with pytest.raises(FeedError):
        build_live_summary(port22, history, topports, usernames, NOW)


def test_username_cutoff_is_30_days():
    names = parse_usernames(
        [{"username": "fresh", "count": 20_000, "lastseen": "2026-08-30"},
         {"username": "stale", "count": 20_000, "lastseen": "2026-08-28"}],
        "2026-09-28",
    )
    assert names == ["fresh"]
