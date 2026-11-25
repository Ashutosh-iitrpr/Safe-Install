"""Parse events the orchestrator itself recorded (resource limits, decoy tampering)."""

import json
from pathlib import Path

from ..contracts import Event


def parse_orchestrator_text(text: str) -> list[Event]:
    events: list[Event] = []
    for line in text.splitlines():
        try:
            record = json.loads(line)
            events.append(Event(
                ts=float(record.get("ts", 0.0)),
                source="orchestrator",
                type=record["type"],
                pid=-1,
                process="orchestrator",
                detail=record.get("detail", {}),
            ))
        except (ValueError, KeyError, TypeError, AttributeError):
            continue
    return events


def parse_orchestrator_file(path: Path) -> list[Event]:
    return parse_orchestrator_text(Path(path).read_text(encoding="utf-8"))
