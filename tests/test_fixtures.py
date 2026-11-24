"""Sanity checks for the independent parser and rules fixtures."""

import json
from pathlib import Path

from safeinstall.contracts import Event, Finding


FIXTURES = Path(__file__).parent / "fixtures"


def test_fixture_contains_twenty_contract_events() -> None:
    events = json.loads((FIXTURES / "events.json").read_text())

    assert len(events) == 20
    assert all(Event.model_validate(event) for event in events)


def test_expected_findings_match_contract() -> None:
    findings = json.loads((FIXTURES / "expected_findings.json").read_text())

    assert {finding["rule_id"] for finding in findings} == {
        "DECOY_READ",
        "CANARY_EXFIL",
        "UNKNOWN_NET",
        "SUSPICIOUS_EXEC",
        "OUTSIDE_WRITE",
        "RESOURCE_ABUSE",
    }
    assert all(Finding.model_validate(finding) for finding in findings)


def test_raw_socket_rejected_event_shape() -> None:
    event = Event(
        ts=1732350003.001,
        source="strace",
        type="net_connect",
        pid=9,
        process="python3",
        detail={
            "host": "1.1.1.1",
            "port": 80,
            "error": "ENETUNREACH",
        },
    )

    assert event.detail["host"] == "1.1.1.1"
    assert event.detail["error"] == "ENETUNREACH"
