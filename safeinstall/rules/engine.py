"""Rules engine for normalized SafeInstall events."""

import base64
import binascii
from pathlib import Path
from urllib.parse import quote, unquote

import yaml

from safeinstall.contracts import Evidence, Event, Finding, Severity, Verdict


RULES_PATH = Path(__file__).with_name("rules.yaml")
ALLOWED_PATH_PREFIXES = (
    "/work/",
    "/tmp/",
    "/src/",
    "/home/sandbox/",
)
DECOY_MARKERS = ("id_rsa", "/.env", "/.aws/credentials")
REGISTRY_ALLOWLIST = frozenset({
    "pypi.org",
    "files.pythonhosted.org",
    "registry.npmjs.org",
})
SUSPICIOUS_COMMANDS = (
    "curl",
    "wget",
    "nc",
    "ncat",
    "bash",
    "sh",
    "base64",
    "powershell",
)


def load_rules(path: str | Path = RULES_PATH) -> dict:
    """Load starter rules and registry allowlist from YAML."""
    data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
    return data


def _event_ref(events: list[Event], target: Event) -> int:
    return events.index(target)


def _canary_variants(tokens: list[str]) -> set[str]:
    variants: set[str] = set()
    for token in tokens:
        if not token:
            continue
        variants.add(token)
        variants.add(token.lower())
        variants.add(base64.b64encode(token.encode()).decode())
        variants.add(base64.b64encode(token.encode()).decode().rstrip("="))
        variants.add(token.encode().hex())
        variants.add(unquote(token))
        variants.add(quote(token, safe=""))
    return variants


def _text_contains_canary(text: str, variants: set[str]) -> bool:
    if not text:
        return False
    lowered = text.lower()
    for variant in variants:
        if variant and variant.lower() in lowered:
            return True
        try:
            decoded = base64.b64decode(variant, validate=True).decode("utf-8", "ignore")
            if decoded and decoded.lower() in lowered:
                return True
        except (binascii.Error, UnicodeDecodeError):
            pass
    return False


def verdict_for(findings: list[Finding]) -> Verdict:
    """Apply critical/high verdict precedence."""
    severities = {finding.severity for finding in findings}
    if Severity.CRITICAL in severities:
        return Verdict.BLOCK
    if Severity.HIGH in severities:
        return Verdict.WARNING
    return Verdict.NO_SUSPICIOUS_BEHAVIOR_OBSERVED


def analyze_events(
    events: list[Event],
    canaries: list[str] | None = None,
    rules_path: str | Path = RULES_PATH,
) -> list[Finding]:
    """Apply starter rules to normalized events."""
    config = load_rules(rules_path)
    rule_config = config.get("rules", {})
    allowlist = frozenset(
        config.get("registry_allowlist", sorted(REGISTRY_ALLOWLIST))
    ) | REGISTRY_ALLOWLIST
    canary_variants = _canary_variants(canaries or [])

    decoy_evidence: list[Evidence] = []
    exfil_evidence: list[Evidence] = []
    unknown_evidence: list[Evidence] = []
    suspicious_evidence: list[Evidence] = []
    outside_write_evidence: list[Evidence] = []
    resource_evidence: list[Evidence] = []

    for event in events:
        ref = _event_ref(events, event)
        detail = event.detail

        if event.type.value == "file_read":
            path = str(detail.get("path", ""))
            if any(marker in path for marker in DECOY_MARKERS):
                decoy_evidence.append(Evidence(
                    event_ref=ref,
                    summary=f"{event.process} opened {path}",
                ))

        if event.type.value == "http_request":
            host = str(detail.get("host", "")).lower().rstrip(".")
            url = str(detail.get("url", ""))
            body = str(detail.get("body_excerpt", ""))
            if canary_variants and _text_contains_canary(
                "\n".join((host, url, body)),
                canary_variants,
            ):
                exfil_evidence.append(Evidence(
                    event_ref=ref,
                    summary=f"Canary token appeared in outbound {event.detail.get('method', 'HTTP')} request",
                ))
            if host and host not in allowlist:
                unknown_evidence.append(Evidence(
                    event_ref=ref,
                    summary=f"{event.process} sent an HTTP request to {host}",
                ))

        if event.type.value == "dns":
            host = str(detail.get("host", "")).lower().rstrip(".")
            if host and host not in allowlist:
                unknown_evidence.append(Evidence(
                    event_ref=ref,
                    summary=f"{event.process} queried {host}",
                ))
            if canary_variants and _text_contains_canary(host, canary_variants):
                exfil_evidence.append(Evidence(
                    event_ref=ref,
                    summary=f"Canary token appeared in DNS name {host}",
                ))

        if event.type.value == "net_connect":
            host = str(detail.get("host", "")).lower().rstrip(".")
            port = detail.get("port")
            if host and not host.startswith(("127.", "10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31.", "192.168.")):
                if host not in allowlist:
                    unknown_evidence.append(Evidence(
                        event_ref=ref,
                        summary=f"{event.process} connected to {host}:{port}",
                    ))

        if event.type.value == "exec":
            cmdline = [str(value) for value in detail.get("cmdline", [])]
            joined = " ".join(cmdline).lower()
            executable = cmdline[0].rsplit("/", 1)[-1] if cmdline else event.process.lower()
            shell_invocation = executable in {"bash", "sh"} and "-c" in cmdline
            suspicious_shell_payload = shell_invocation and any(
                marker in joined
                for marker in (
                    "curl ",
                    "wget ",
                    "nc ",
                    "ncat ",
                    "base64 ",
                    "/.env",
                    "id_rsa",
                    ".aws/credentials",
                )
            )
            direct_suspicious = executable in SUSPICIOUS_COMMANDS and executable not in {"bash", "sh"}
            if direct_suspicious or suspicious_shell_payload:
                suspicious_evidence.append(Evidence(
                    event_ref=ref,
                    summary=f"{event.process} executed suspicious command: {' '.join(cmdline)}",
                ))

        if event.type.value == "file_write":
            path = str(detail.get("path", ""))
            if (
                path.startswith("/")
                and not any(path.startswith(prefix) for prefix in ALLOWED_PATH_PREFIXES)
            ):
                outside_write_evidence.append(Evidence(
                    event_ref=ref,
                    summary=f"{event.process} wrote {path}",
                ))

        if event.type.value == "resource_limit":
            suspicious_evidence = suspicious_evidence
            resource_evidence.append(Evidence(
                event_ref=ref,
                summary=f"{event.process} reached a resource limit",
            ))

    findings: list[Finding] = []

    def add(rule_id: str, evidence: list[Evidence]) -> None:
        if not evidence:
            return
        rule = rule_config.get(rule_id, {})
        findings.append(Finding(
            rule_id=rule_id,
            severity=rule.get("severity", "medium"),
            title=rule.get("title", rule_id),
            evidence=evidence,
        ))

    add("DECOY_READ", decoy_evidence)
    add("CANARY_EXFIL", exfil_evidence)
    add("UNKNOWN_NET", unknown_evidence)
    add("SUSPICIOUS_EXEC", suspicious_evidence)
    add("OUTSIDE_WRITE", outside_write_evidence)
    add("RESOURCE_ABUSE", resource_evidence)
    return findings
