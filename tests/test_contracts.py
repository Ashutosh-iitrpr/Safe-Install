"""Tests for the public event, finding, and artifact contracts."""

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from safeinstall.contracts import (
    Event,
    EventSource,
    EventType,
    Evidence,
    Finding,
    RunArtifacts,
    RunMeta,
    Severity,
    Verdict,
)


def test_event_matches_normalized_schema() -> None:
    event = Event(
        ts=1732350000.123,
        source="strace",
        type="file_read",
        pid=123,
        process="python3",
        detail={"path": "/home/sandbox/.env"},
    )

    assert event.source is EventSource.STRACE
    assert event.type is EventType.FILE_READ
    assert event.model_dump(mode="json")["detail"] == {"path": "/home/sandbox/.env"}


def test_finding_serializes_nested_evidence() -> None:
    finding = Finding(
        rule_id="DECOY_READ",
        severity="critical",
        title="Read decoy credential file",
        evidence=[Evidence(event_ref=17, summary="python3 opened /home/sandbox/.env")],
    )

    assert finding.model_dump(mode="json")["evidence"][0]["event_ref"] == 17
    assert finding.severity is Severity.CRITICAL


def test_run_artifacts_capture_meta_and_verdict() -> None:
    metadata = RunMeta(
        input="requests",
        started_at=datetime(2026, 11, 23, tzinfo=timezone.utc),
        limits={"timeout_seconds": 120},
    )
    artifacts = RunArtifacts(
        run_id="run-001",
        meta=metadata,
        verdict=Verdict.BLOCK,
    )

    assert artifacts.verdict is Verdict.BLOCK
    assert artifacts.meta.limits["timeout_seconds"] == 120


def test_contract_rejects_unknown_fields() -> None:
    with pytest.raises(ValidationError):
        Event(
            ts=1.0,
            source="gateway",
            type="dns",
            pid=1,
            process="dnsmasq",
            unexpected="value",
        )
