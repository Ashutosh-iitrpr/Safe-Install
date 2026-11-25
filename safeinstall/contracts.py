"""Typed data contracts shared by parsers, rules, and report renderers."""

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class EventSource(StrEnum):
    """Source artifact that produced a normalized event."""

    STRACE = "strace"
    GATEWAY = "gateway"
    FSDIFF = "fsdiff"


class EventType(StrEnum):
    """Normalized behavioral event types."""

    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    EXEC = "exec"
    NET_CONNECT = "net_connect"
    DNS = "dns"
    HTTP_REQUEST = "http_request"
    RESOURCE_LIMIT = "resource_limit"


class Severity(StrEnum):
    """Finding severity, ordered by the rules engine externally."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    INFO = "info"


class Verdict(StrEnum):
    """User-facing run verdict."""

    BLOCK = "BLOCK"
    WARNING = "WARNING"
    NO_SUSPICIOUS_BEHAVIOR_OBSERVED = "NO SUSPICIOUS BEHAVIOR OBSERVED"
    INCONCLUSIVE = "INCONCLUSIVE"

class ContractModel(BaseModel):
    """Base model that rejects fields outside the public contract."""

    model_config = ConfigDict(extra="forbid")


class Event(ContractModel):
    """A normalized observation emitted by an artifact parser."""

    ts: float
    source: EventSource
    type: EventType
    pid: int
    process: str
    detail: dict[str, Any] = Field(default_factory=dict)


class Evidence(ContractModel):
    """A concise explanation connecting a finding to an event."""

    event_ref: int
    summary: str


class Finding(ContractModel):
    """A rule-engine finding and its supporting evidence."""

    rule_id: str
    severity: Severity
    title: str
    evidence: list[Evidence] = Field(default_factory=list)


class RunMeta(ContractModel):
    """Metadata persisted as ``runs/<run_id>/meta.json``."""

    input: str
    resolved_version: str | None = None
    started_at: datetime
    finished_at: datetime | None = None
    limits: dict[str, Any] = Field(default_factory=dict)
    exit_code: int | None = None
    peak_mem: int | None = None


class RunArtifacts(ContractModel):
    """Manifest for the JSON and log artifacts produced by a run."""

    run_id: str
    meta: RunMeta
    events: list[Event] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    verdict: Verdict | None = None
