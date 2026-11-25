"""Rules engine for normalized SafeInstall events."""

import base64
import binascii
from pathlib import Path
from urllib.parse import quote, unquote
import re
import ipaddress
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
SENSITIVE_WRITE_MARKERS = (
    "/.bashrc", "/.bash_profile", "/.profile", "/.zshrc", "/.ssh/", "/.aws/",
    "/.npmrc", "/.pypirc", "/.git-credentials", "/.config/autostart/",
    "/.config/systemd/", "/.git/hooks/", "/cron",
)
SRC_BUILD_MARKERS = ("/build/", "/dist/", ".egg-info", "/__pycache__/", "/node_modules/")
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
PROXY_PORT = 3128


def _is_infrastructure(host: str, port: object) -> bool:
    """Loopback and the SafeInstall gateway proxy are not suspicious; everything else is."""
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_loopback or (ip.is_private and str(port) == str(PROXY_PORT))


def _is_suspicious_write(path: str) -> bool:
    if path in ("/src", "/work", "/tmp", "/home/sandbox"):   # mount points, not writes
        return False
    if not path.startswith("/"):
        return False
    if any(marker in path for marker in SENSITIVE_WRITE_MARKERS + DECOY_MARKERS):
        return True
    if path.startswith("/src/"):
        return not any(marker in path for marker in SRC_BUILD_MARKERS)
    return not any(path.startswith(prefix) for prefix in ALLOWED_PATH_PREFIXES)


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


_B64_RE = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_HEX_RE = re.compile(r"(?:[0-9a-fA-F]{2}){16,}")


def _decoded_views(text: str) -> list[str]:
    """The text plus every base64/hex/url-decoded view of it (works at any base64 alignment)."""
    views = [text, unquote(text)]
    for blob in _B64_RE.findall(text):
        padded = blob + "=" * (-len(blob) % 4)
        for decode in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                views.append(decode(padded).decode("utf-8", "ignore"))
            except (binascii.Error, ValueError):
                pass
    for blob in _HEX_RE.findall(text):
        views.append(bytes.fromhex(blob).decode("utf-8", "ignore"))
    return views


def _text_contains_canary(text: str, variants: set[str]) -> bool:
    if not text:
        return False
    needles = [variant.lower() for variant in variants if variant]
    for view in _decoded_views(text):
        lowered = view.lower()
        if any(needle in lowered for needle in needles):
            return True
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
            if host and not _is_infrastructure(host, port):
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
            if _is_suspicious_write(path):
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
