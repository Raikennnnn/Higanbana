import json

from collector.datasets import DATASETS, adapted_lines
from collector.parser import parse_lines

CYBERLAB = DATASETS["cyberlab"]


def test_legacy_command_events_become_command_input():
    lines = [
        json.dumps({"timestamp": "2019-05-18T00:00:01Z", "eventid": "cowrie.command.success",
                    "session": "ab12cd34", "src_ip": "4fabc41d5c58a751", "input": "uname -a"}),
        json.dumps({"timestamp": "2019-05-18T00:00:02Z", "eventid": "cowrie.command.failed",
                    "session": "ab12cd34", "src_ip": "4fabc41d5c58a751", "input": "foo"}),
    ]
    events, errors = parse_lines(adapted_lines(lines, CYBERLAB), CYBERLAB.sensor_id)
    assert not errors
    assert [e.eventid for e in events] == ["cowrie.command.input"] * 2
    assert events[0].payload["legacy_eventid"] == "cowrie.command.success"


def test_other_events_and_bad_lines_pass_through():
    lines = [
        json.dumps({"timestamp": "2019-05-18T00:00:01Z", "eventid": "cowrie.session.connect",
                    "session": "ab12cd34", "src_ip": "4fabc41d5c58a751", "country": "Ireland"}),
        "not json",
    ]
    events, errors = parse_lines(adapted_lines(lines, CYBERLAB), CYBERLAB.sensor_id)
    assert events[0].eventid == "cowrie.session.connect"
    assert events[0].payload["country"] == "Ireland"
    assert [n for n, _ in errors] == [2]


def test_dataset_metadata_is_attributed():
    assert CYBERLAB.license == "CC BY 4.0"
    assert CYBERLAB.url.startswith("https://doi.org/")
