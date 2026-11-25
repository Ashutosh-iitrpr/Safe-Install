"""Rich terminal report rendering."""

from collections import Counter
from io import StringIO
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from safeinstall.contracts import Event, RunArtifacts, Verdict


TEMPLATE_PATH = Path(__file__).with_name("template.html")


def _detail_summary(event: Event) -> str:
    detail = event.detail
    if event.type.value in {"file_read", "file_write"}:
        return str(detail.get("path", ""))
    if event.type.value == "exec":
        return " ".join(str(value) for value in detail.get("cmdline", []))
    if event.type.value in {"dns", "net_connect"}:
        host = detail.get("host", "")
        port = detail.get("port")
        return f"{host}:{port}" if port is not None else str(host)
    if event.type.value == "http_request":
        return f"{detail.get('method', 'HTTP')} {detail.get('url', detail.get('host', ''))}"
    return ", ".join(f"{key}={value}" for key, value in detail.items())


def _verdict_border(verdict: Verdict) -> str:
    return {
        Verdict.BLOCK: "red",
        Verdict.WARNING: "yellow",
        Verdict.NO_SUSPICIOUS_BEHAVIOR_OBSERVED: "green",
        Verdict.INCONCLUSIVE: "yellow",
    }[verdict]


def _verdict_message(verdict: Verdict) -> str:
    if verdict is Verdict.BLOCK:
        return "Package blocked: critical behavior detected"
    if verdict is Verdict.WARNING:
        return "Package allowed with warnings"
    if verdict is Verdict.INCONCLUSIVE:
        return "Run incomplete: no conclusion can be drawn"
    return "No suspicious behavior observed"


def render_terminal(
    artifacts: RunArtifacts,
    console: Console | None = None,
    show_timeline: bool = True,
) -> None:
    """Render a complete terminal report for normalized run artifacts."""
    output = console or Console()
    verdict = artifacts.verdict or Verdict.NO_SUSPICIOUS_BEHAVIOR_OBSERVED

    output.print(
        Panel(
            Text(_verdict_message(verdict), justify="center"),
            title=f"SafeInstall verdict: {verdict.value}",
            border_style=_verdict_border(verdict),
        )
    )

    findings = Table(title="Findings", expand=True)
    findings.add_column("Severity", style="bold")
    findings.add_column("Rule")
    findings.add_column("Title")
    findings.add_column("Evidence", justify="right")
    if artifacts.findings:
        for finding in artifacts.findings:
            findings.add_row(
                finding.severity.value.upper(),
                finding.rule_id,
                finding.title,
                str(len(finding.evidence)),
            )
    else:
        findings.add_row("-", "-", "No findings", "0")
    output.print(findings)

    if show_timeline:
        timeline = Table(title="Timeline", expand=True)
        timeline.add_column("Time", justify="right")
        timeline.add_column("Source")
        timeline.add_column("Process")
        timeline.add_column("Activity")
        for event in sorted(artifacts.events, key=lambda item: item.ts):
            timeline.add_row(
                f"{event.ts:.3f}",
                event.source.value,
                event.process,
                f"{event.type.value}: {_detail_summary(event)}",
            )
        if not artifacts.events:
            timeline.add_row("-", "-", "-", "No events captured")
        output.print(timeline)
    else:
        output.print(f"Timeline hidden ({len(artifacts.events)} events); see report.html for the full list.")

    hosts = Counter(
        str(event.detail["host"])
        for event in artifacts.events
        if event.type.value in {"dns", "net_connect", "http_request"}
        and event.detail.get("host")
    )
    network = Table(title="Network summary", expand=True)
    network.add_column("Host")
    network.add_column("Events", justify="right")
    if hosts:
        for host, count in sorted(hosts.items()):
            network.add_row(host, str(count))
    else:
        network.add_row("No network activity captured", "0")
    output.print(network)


def terminal_report_text(artifacts: RunArtifacts) -> str:
    """Return the terminal report as plain text, useful for tests and logs."""
    stream = StringIO()
    render_terminal(
        artifacts,
        Console(file=stream, force_terminal=False, color_system=None),
    )
    return stream.getvalue()


def _html_context(artifacts: RunArtifacts) -> dict:
    verdict = artifacts.verdict or Verdict.NO_SUSPICIOUS_BEHAVIOR_OBSERVED
    hosts = Counter(
        str(event.detail["host"])
        for event in artifacts.events
        if event.type.value in {"dns", "net_connect", "http_request"}
        and event.detail.get("host")
    )
    findings = [
        {
            "rule_id": finding.rule_id,
            "severity": finding.severity.value,
            "title": finding.title,
            "evidence": [
                {
                    "summary": evidence.summary,
                    "event": (
                        artifacts.events[evidence.event_ref]
                        if 0 <= evidence.event_ref < len(artifacts.events)
                        else None
                    ),
                }
                for evidence in finding.evidence
            ],
        }
        for finding in artifacts.findings
    ]
    events = [
        {
            "timestamp": f"{event.ts:.3f}",
            "source": event.source.value,
            "process": event.process,
            "type": event.type.value,
            "summary": _detail_summary(event),
        }
        for event in sorted(artifacts.events, key=lambda item: item.ts)
    ]
    return {
        "run_id": artifacts.run_id,
        "meta": artifacts.meta,
        "verdict": verdict.value,
        "verdict_class": verdict.name.lower(),
        "verdict_message": _verdict_message(verdict),
        "findings": findings,
        "events": events,
        "hosts": sorted(hosts.items()),
    }


def render_html(artifacts: RunArtifacts) -> str:
    """Render normalized run artifacts as a standalone HTML report."""
    environment = Environment(
        loader=FileSystemLoader(TEMPLATE_PATH.parent),
        autoescape=select_autoescape(("html", "xml")),
    )
    template = environment.get_template(TEMPLATE_PATH.name)
    return template.render(**_html_context(artifacts))


def write_html_report(artifacts: RunArtifacts, path: str | Path) -> Path:
    """Render and write an HTML report, returning its resolved path."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(render_html(artifacts), encoding="utf-8")
    return destination
