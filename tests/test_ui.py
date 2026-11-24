from datetime import datetime, timezone

from safeinstall.contracts import Event, RunArtifacts, RunMeta, Verdict
from safeinstall.ui import finding_rows, network_rows, timeline_rows


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
