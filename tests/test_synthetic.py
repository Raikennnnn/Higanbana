import ipaddress
from collections import defaultdict
from datetime import datetime, timezone
from urllib.parse import urlparse

from collector.synthetic import DOC_NETWORKS, generate

START = datetime(2026, 1, 1, tzinfo=timezone.utc)


def _events(n=300, seed=11):
    return list(generate(sessions=n, seed=seed, start=START))


def test_same_seed_same_output():
    assert _events(seed=5) == _events(seed=5)
    assert _events(seed=5) != _events(seed=6)


def test_source_ips_are_documentation_ranges_only():
    for ev in _events():
        ip = ipaddress.ip_address(ev["src_ip"])
        assert any(ip in net for net in DOC_NETWORKS), ip


def test_urls_use_reserved_hosts_only():
    for ev in _events():
        if "url" not in ev:
            continue
        host = urlparse(ev["url"]).hostname
        if host.endswith(".example") or host.endswith(".example.net"):
            continue
        ip = ipaddress.ip_address(host)
        assert any(ip in net for net in DOC_NETWORKS), host


def test_every_session_opens_and_closes():
    by_session = defaultdict(list)
    for ev in _events():
        by_session[ev["session"]].append(ev["eventid"])
    for eventids in by_session.values():
        assert eventids[0] == "cowrie.session.connect"
        assert eventids[-1] == "cowrie.session.closed"


def test_all_behaviours_appear():
    eventids = {ev["eventid"] for ev in _events()}
    assert {
        "cowrie.login.failed",
        "cowrie.login.success",
        "cowrie.command.input",
        "cowrie.session.file_download.failed",
    } <= eventids
