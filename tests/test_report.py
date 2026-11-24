from datetime import datetime, timezone
import json
from pathlib import Path

from safeinstall.contracts import Event, Finding, RunArtifacts, RunMeta, Verdict
from safeinstall.report.render import render_html, terminal_report_text, write_html_report


FIXTURE_DIR = Path(__file__).parent / "fixtures"


def _artifacts() -> RunArtifacts:
    events = [
        Event.model_validate(raw)
        for raw in json.loads((FIXTURE_DIR / "events.json").read_text())
    ]
    findings = [
        Finding.model_validate(raw)
        for raw in json.loads(
            (FIXTURE_DIR / "expected_findings.json").read_text()
        )
    ]
    return RunArtifacts(
        run_id="report-test",
        meta=RunMeta(
            input="fixture-pkg",
            started_at=datetime.now(timezone.utc),
        ),
        events=events,
        findings=findings,
        verdict=Verdict.BLOCK,
    )


def test_terminal_report_contains_verdict_findings_timeline_and_network() -> None:
    report = terminal_report_text(_artifacts())

    assert "SafeInstall verdict: BLOCK" in report
    assert "Findings" in report
    assert "DECOY_READ" in report
    assert "Timeline" in report
    assert "file_read: /home/sandbox/.env" in report
    assert "Network summary" in report
    assert "collector.example" in report


def test_terminal_report_handles_clean_run() -> None:
    artifacts = _artifacts().model_copy(
        update={"events": [], "findings": [], "verdict": Verdict.NO_SUSPICIOUS_BEHAVIOR_OBSERVED}
    )

    report = terminal_report_text(artifacts)

    assert "No suspicious behavior observed" in report
    assert "No findings" in report
    assert "No events captured" in report
    assert "No network activity captured" in report


def test_html_report_contains_sections_and_escapes_values(tmp_path) -> None:
    artifacts = _artifacts().model_copy(
        update={
            "meta": _artifacts().meta.model_copy(update={"input": "<unsafe-package>"}),
        }
    )

    report = render_html(artifacts)
    output_path = write_html_report(artifacts, tmp_path / "report.html")

    assert "SafeInstall verdict: BLOCK" in report
    assert "Read decoy credential file" in report
    assert "Event timeline" in report
    assert "Network summary" in report
    assert "collector.example" in report
    assert "&lt;unsafe-package&gt;" in report
    assert output_path.read_text(encoding="utf-8") == report
