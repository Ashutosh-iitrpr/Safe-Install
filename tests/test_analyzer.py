import json
from datetime import datetime, timezone
from pathlib import Path

from safeinstall.analyzer import analyze_run
from safeinstall.contracts import Verdict


def test_analyzer_persists_events_findings_and_reports(tmp_path: Path) -> None:
    (tmp_path / "meta.json").write_text(
        json.dumps(
            {
                "input": "fixture-pkg",
                "started_at": datetime.now(timezone.utc).isoformat(),
                "exit_code": 0,
            }
        ),
        encoding="utf-8",
    )
    (tmp_path / "strace.log").write_text(
        '12 1732350000.100 openat(AT_FDCWD, "/home/sandbox/.env", O_RDONLY) = 3\n',
        encoding="utf-8",
    )
    (tmp_path / "gateway.jsonl").write_text(
        '{"type":"http_request","method":"POST","host":"collector.example",'
        '"url":"http://collector.example/upload","body_excerpt":"CANARY_TOKEN"}\n',
        encoding="utf-8",
    )
    (tmp_path / "canaries.json").write_text(
        json.dumps([{"token": "CANARY_TOKEN"}]),
        encoding="utf-8",
    )
    (tmp_path / "fsdiff.txt").write_text("", encoding="utf-8")

    artifacts = analyze_run(tmp_path, "analyzer-test")

    assert artifacts.verdict is Verdict.BLOCK
    assert {finding.rule_id for finding in artifacts.findings} == {
        "DECOY_READ",
        "CANARY_EXFIL",
        "UNKNOWN_NET",
    }
    assert (tmp_path / "events.json").exists()
    assert (tmp_path / "findings.json").exists()
    assert (tmp_path / "report.json").exists()
    assert (tmp_path / "report.html").exists()
