"""Parse gateway JSONL records into normalized events."""

import json
from pathlib import Path
from typing import Iterable

from safeinstall.contracts import Event


def parse_gateway_lines(lines: Iterable[str]) -> list[Event]:
    """Convert gateway JSONL lines into normalized Event contracts."""
    events: list[Event] = []

    for index, line in enumerate(lines):
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        if not isinstance(record, dict):
            continue

        ts = float(record.get("ts", 0.0))
        pid = int(record.get("pid", -1))
        process = str(record.get("process", "gateway"))
        record_type = str(record.get("type", "")).lower()

        if record_type == "dns":
            host = record.get("host")
            if not host:
                continue
            events.append(Event(
                ts=ts if ts else float(index),
                source="gateway",
                type="dns",
                pid=pid,
                process=process,
                detail={
                    "host": str(host),
                    "query_type": record.get("query_type", 1),
                },
            ))
            continue

        if record_type == "http_request":
            host = record.get("host")
            method = str(record.get("method", "")).upper()
            if method == "CONNECT" and host:
                events.append(Event(
                    ts=ts if ts else float(index),
                    source="gateway",
                    type="net_connect",
                    pid=pid,
                    process=process,
                    detail={
                        "host": str(host),
                        "port": int(record.get("port", 443)),
                        "allowed": bool(record.get("allowed", False)),
                    },
                ))
                continue

            detail: dict[str, object] = {}
            if method:
                detail["method"] = method
            if record.get("url"):
                detail["url"] = str(record["url"])
            if record.get("host"):
                detail["host"] = str(record["host"])
            if record.get("port") is not None:
                detail["port"] = int(record["port"])
            if "body_excerpt" in record:
                detail["body_excerpt"] = str(record["body_excerpt"])
            if "body_length" in record:
                detail["body_length"] = int(record["body_length"])
            if "body_sha256" in record:
                detail["body_sha256"] = str(record["body_sha256"])
            if "allowed" in record:
                detail["allowed"] = bool(record["allowed"])
            events.append(Event(
                ts=ts if ts else float(index),
                source="gateway",
                type="http_request",
                pid=pid,
                process=process,
                detail=detail,
            ))

    return events


def parse_gateway_text(text: str) -> list[Event]:
    """Parse gateway JSONL text."""
    return parse_gateway_lines(text.splitlines())


def parse_gateway_file(path: str | Path) -> list[Event]:
    """Read a gateway JSONL artifact and normalize it."""
    return parse_gateway_text(
        Path(path).read_text(encoding="utf-8", errors="replace")
    )
