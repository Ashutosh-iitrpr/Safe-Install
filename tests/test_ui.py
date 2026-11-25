from datetime import datetime, timezone

from safeinstall.contracts import Event, RunArtifacts, RunMeta, Verdict
from safeinstall.contracts import Finding, Severity
from safeinstall.ui import finding_rows, network_rows, recent_reports, severity_counts, timeline_rows


def _artifacts() -> RunArtifacts:
    return RunArtifacts(
        run_id="ui-test",
        meta=RunMeta(input="fixture", started_at=datetime.now(timezone.utc)),
        events=[
            Event(
                ts=2,
                source="gateway",
                type="http_request",
                pid=1,
                process="python",
                detail={"host": "collector.example", "method": "POST"},
            ),
            Event(
                ts=1,
                source="strace",
                type="file_read",
                pid=1,
                process="python",
                detail={"path": "/home/sandbox/.env"},
            ),
        ],
        verdict=Verdict.BLOCK,
    )


def test_ui_rows_are_sorted_and_summarized() -> None:
    artifacts = _artifacts()

    assert timeline_rows(artifacts)[0]["activity"] == "file_read"
    assert network_rows(artifacts) == [{"host": "collector.example", "events": 1}]
    assert finding_rows(artifacts) == []


def test_ui_severity_counts() -> None:
    artifacts = _artifacts()
    artifacts.findings = [
        Finding(
            rule_id="DECOY_READ",
            severity=Severity.CRITICAL,
            title="Read decoy credential file",
            evidence=[],
        )
    ]

    assert severity_counts(artifacts)["CRITICAL"] == 1
    assert severity_counts(artifacts)["HIGH"] == 0


def test_recent_reports(tmp_path) -> None:
    run_dir = tmp_path / "20261124T120000-abcdef01"
    run_dir.mkdir()
    artifacts = _artifacts()
    (run_dir / "report.json").write_text(
        artifacts.model_dump_json(),
        encoding="utf-8",
    )

    reports = recent_reports(tmp_path)

    assert len(reports) == 1
    assert reports[0]["run_id"] == "ui-test"
    assert reports[0]["verdict"] == "BLOCK"
