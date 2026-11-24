"""Tests for the normalized-event rules engine."""

import base64
import json
from pathlib import Path

from safeinstall.contracts import Event
from safeinstall.rules.engine import analyze_events, verdict_for


FIXTURE_DIR = Path(__file__).parent / "fixtures"


def test_rules_engine_matches_fixture_findings() -> None:
    raw_events = json.loads((FIXTURE_DIR / "events.json").read_text())
    events = [Event.model_validate(raw) for raw in raw_events]
    findings = analyze_events(events, canaries=["CANARY_ENV_7f3a"])

    assert {finding.rule_id for finding in findings} == {
        "DECOY_READ",
        "CANARY_EXFIL",
        "UNKNOWN_NET",
        "SUSPICIOUS_EXEC",
        "OUTSIDE_WRITE",
        "RESOURCE_ABUSE",
    }
    assert verdict_for(findings).value == "BLOCK"


def test_canary_exfil_detects_base64_hex_and_urlencoded() -> None:
    token = "CANARY_A1B2"
    text_variants = [
        base64.b64encode(token.encode()).decode(),
        token.encode().hex(),
        "CANARY%5FA1B2",
    ]
    events = [
        Event(
            ts=index,
            source="gateway",
            type="http_request",
            pid=10,
            process="python3",
            detail={
                "method": "POST",
                "host": "evil.example",
                "url": "http://evil.example/upload",
                "body_excerpt": text,
            },
        )
        for index, text in enumerate(text_variants)
    ]

    findings = analyze_events(events, canaries=[token])
    assert any(finding.rule_id == "CANARY_EXFIL" for finding in findings)


def test_clean_registry_activity_has_no_findings() -> None:
    events = [
        Event(
            ts=1.0,
            source="gateway",
            type="http_request",
            pid=10,
            process="pip",
            detail={
                "method": "GET",
                "host": "pypi.org",
                "url": "https://pypi.org/simple",
            },
        ),
        Event(
            ts=2.0,
            source="strace",
            type="exec",
            pid=10,
            process="python3",
            detail={"cmdline": ["python3", "-m", "pip", "install", "requests"]},
        ),
    ]

    assert analyze_events(events) == []


def test_relative_pip_wheel_writes_are_not_outside_writes() -> None:
    events = [
        Event(
            ts=1.0,
            source="strace",
            type="file_write",
            pid=10,
            process="python",
            detail={"path": "requests-2.34.2-py3-none-any.whl"},
        )
    ]

    assert analyze_events(events) == []
