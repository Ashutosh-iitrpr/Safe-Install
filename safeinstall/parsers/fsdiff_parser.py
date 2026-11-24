"""Parse Docker filesystem-diff lines into normalized events."""

from pathlib import Path

from safeinstall.contracts import Event


CHANGE_KINDS = {
    "0": "changed",
    "C": "changed",
    "1": "added",
    "A": "added",
    "2": "deleted",
    "D": "deleted",
}


def parse_fsdiff_text(text: str) -> list[Event]:
    """Convert Docker diff text into file_write events."""
    events: list[Event] = []

    for index, line in enumerate(text.splitlines()):
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        kind, path = parts
        operation = CHANGE_KINDS.get(kind)
        if operation is None:
            continue
        if not path.startswith("/"):
            continue
        events.append(Event(
            ts=float(index),
            source="fsdiff",
            type="file_write",
            pid=-1,
            process="container-diff",
            detail={
                "path": path,
                "operation": operation,
            },
        ))

    return events


def parse_fsdiff_file(path: str | Path) -> list[Event]:
    """Read an fsdiff.txt artifact and normalize it."""
    return parse_fsdiff_text(
        Path(path).read_text(encoding="utf-8", errors="replace")
    )
