"""Build normalized findings and reports from one completed run directory."""

import json
import time
from pathlib import Path
from typing import Any

from .contracts import RunArtifacts, RunMeta, Verdict
from .parsers.fsdiff_parser import parse_fsdiff_file
from .parsers.gateway_parser import parse_gateway_file
from .parsers.strace_parser import parse_strace_file
from .report.render import render_html
from .rules.engine import analyze_events, verdict_for
from .parsers.orchestrator_parser import parse_orchestrator_file


def _events_from(path: Path, parser) -> list:
    if not path.exists():
        return []
    return parser(path)


def _canaries(run_dir: Path) -> list[str]:
    path = run_dir / "canaries.json"
    if not path.exists():
        return []
    entries = json.loads(path.read_text(encoding="utf-8"))
    return [
        str(entry["token"])
        for entry in entries
        if isinstance(entry, dict) and entry.get("token")
    ]

def _run_incomplete(directory: Path, meta: RunMeta) -> bool:
    trace = directory / "strace.log"
    return (
        (directory / "orchestrator-error.txt").exists()
        or not trace.exists()
        or trace.stat().st_size == 0
        or meta.exit_code != 0
    )

def analyze_run(run_dir: str | Path, run_id: str) -> RunArtifacts:
    """Parse, analyze, and persist all available artifacts for a run."""
    directory = Path(run_dir)
    meta = RunMeta.model_validate(
        json.loads((directory / "meta.json").read_text(encoding="utf-8"))
    )
    end_ts = meta.finished_at.timestamp() if meta.finished_at else time.time()
    fsdiff_events = [
        event.model_copy(update={"ts": end_ts})
        for event in _events_from(directory / "fsdiff.txt", parse_fsdiff_file)
    ]
    events = (
        _events_from(directory / "strace.log", parse_strace_file)
        + _events_from(directory / "gateway.jsonl", parse_gateway_file)
        + fsdiff_events
        + _events_from(directory / "orchestrator-events.jsonl", parse_orchestrator_file)
    )
    events.sort(key=lambda event: event.ts)
    findings = analyze_events(events, canaries=_canaries(directory))
    verdict = verdict_for(findings)
    if verdict is Verdict.NO_SUSPICIOUS_BEHAVIOR_OBSERVED and _run_incomplete(directory, meta):
        verdict = Verdict.INCONCLUSIVE
    artifacts = RunArtifacts(
        run_id=run_id, 
        meta=meta, 
        events=events, 
        findings=findings,
        verdict=verdict,                                   # was verdict_for(findings)
    )

    _write_json(directory / "events.json", [event.model_dump(mode="json") for event in events])
    _write_json(
        directory / "findings.json",
        [finding.model_dump(mode="json") for finding in findings],
    )
    _write_json(directory / "report.json", artifacts.model_dump(mode="json"))
    (directory / "report.html").write_text(render_html(artifacts), encoding="utf-8")
    return artifacts


def _write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
