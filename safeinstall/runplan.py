"""Pure helpers that decide how a run is configured and how its artifacts are trusted.

No Docker imports on purpose: everything here is unit-testable without a daemon.
"""

from __future__ import annotations

import os
import secrets
import stat
import string
from pathlib import Path
from urllib.parse import urlsplit

from .config import REGISTRY_ALLOWLIST

SANDBOX_HOME = "/home/sandbox"
MAX_ARTIFACT_BYTES = 256 * 1024 * 1024

# Gateway container: DNS sink in the background, HTTP proxy in the foreground.
GATEWAY_COMMAND = (
    "python /opt/safeinstall/dns_server.py --log /gateway-log/gateway.jsonl & "
    "exec python /opt/safeinstall/proxy.py --host 0.0.0.0 --port 3128 "
    "--log /gateway-log/gateway.jsonl"
)

_ALNUM = string.ascii_letters + string.digits
_UPPER = string.ascii_uppercase + string.digits


def _rand(length: int, alphabet: str = _ALNUM) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(length))


def is_local_target(target: str) -> bool:
    """Only explicit paths are local. A bare name such as `requests` is always a package."""
    if "://" in target or target.startswith(("git+", "@")):
        return False
    return target.startswith((".", "/", "~")) or os.sep in target


def allowlist_env() -> str:
    return ",".join(sorted(REGISTRY_ALLOWLIST))


def make_canaries() -> list[dict[str, str]]:
    """Fresh realistic-looking fake secrets, generated on the host (never read back from the sandbox)."""
    file_tokens = {
        ".env": "sk_live_" + _rand(24),
        ".ssh/id_rsa": _rand(70),
        ".aws/credentials": _rand(40),
        ".npmrc": "npm_" + _rand(36),
        ".pypirc": "pypi-AgEIcHlwaS5vcmc" + _rand(50),
        ".git-credentials": "ghp_" + _rand(36),
    }
    entries = [
        {"kind": kind, "path": f"{SANDBOX_HOME}/{kind}", "token": token}
        for kind, token in file_tokens.items()
    ]
    env_tokens = {
        "GITHUB_TOKEN": "ghp_" + _rand(36),
        "AWS_SECRET_ACCESS_KEY": _rand(40),
        "AWS_ACCESS_KEY_ID": "AKIA" + _rand(16, _UPPER),
    }
    entries += [
        {"kind": f"env:{name}", "path": "", "token": token}
        for name, token in env_tokens.items()
    ]
    return entries


def canary_env(entries: list[dict[str, str]]) -> dict[str, str]:
    """Sandbox environment: env-var canaries plus the JSON that make-decoys consumes."""
    import json

    env = {e["kind"][4:]: e["token"] for e in entries if e["kind"].startswith("env:")}
    env["SAFEINSTALL_CANARIES"] = json.dumps(
        {e["kind"]: e["token"] for e in entries if not e["kind"].startswith("env:")}
    )
    return env


def safe_copy(src: Path, dst: Path, max_bytes: int = MAX_ARTIFACT_BYTES) -> bool:
    """Copy a sandbox-written file to the host run dir; refuse symlinks and non-files."""
    try:
        fd = os.open(src, os.O_RDONLY | os.O_NOFOLLOW)
    except OSError:
        return False
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            return False
        data = handle.read(max_bytes)
    dst.write_bytes(data)
    return True


def decoy_tamper_paths(log_text: str) -> list[str]:
    """Decoys whose end-of-run hash differs from the start-of-run hash (or that vanished).

    The entrypoint prints these lines to stdout, which Docker captures on the host.
    """
    start: dict[str, str] = {}
    end: dict[str, str] = {}
    for line in log_text.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0] == "SAFEINSTALL_DECOY_START":
            start[parts[2]] = parts[1]
        elif len(parts) == 3 and parts[0] == "SAFEINSTALL_DECOY_END":
            end[parts[2]] = parts[1]
    return sorted(path for path, digest in start.items() if end.get(path) != digest)


def pip_report_from_log(log_text: str) -> str | None:
    """The JSON between the entrypoint's report markers, or None."""
    begin, finish = "SAFEINSTALL_PIP_REPORT_BEGIN", "SAFEINSTALL_PIP_REPORT_END"
    if begin not in log_text or finish not in log_text:
        return None
    return log_text.split(begin, 1)[1].split(finish, 1)[0].strip() or None


def pinned_requirements(report: dict) -> tuple[str | None, str | None]:
    """(hash-pinned requirements text, 'name==version' of the requested package) from `pip --report`.

    Returns (None, None) when anything cannot be pinned by sha256 from an allowlisted host.
    """
    lines: list[str] = []
    requested: str | None = None
    for item in report.get("install", []):
        meta = item.get("metadata", {})
        download = item.get("download_info", {})
        archive = download.get("archive_info", {})
        digest = (archive.get("hashes") or {}).get("sha256")
        raw = str(archive.get("hash", ""))
        if not digest and raw.startswith("sha256="):
            digest = raw[len("sha256="):]
        host = urlsplit(str(download.get("url", ""))).hostname or ""
        name, version = meta.get("name"), meta.get("version")
        if not (name and version and digest) or host not in REGISTRY_ALLOWLIST:
            return None, None
        lines.append(f"{name}=={version} --hash=sha256:{digest}")
        if item.get("requested"):
            requested = f"{name}=={version}"
    return ("\n".join(lines) + "\n" if lines else None), requested


def orchestrator_events(
    *,
    oom_killed: bool,
    exit_code: int,
    timed_out: bool,
    tampered_decoys: list[str],
    timeout_seconds: int,
    now: float,
) -> list[dict]:
    """Event records the orchestrator itself observed (resource limits, decoy tampering)."""
    records: list[dict] = []
    if oom_killed:
        records.append({"ts": now, "type": "resource_limit",
                        "detail": {"resource": "memory", "message": "sandbox killed by the memory limit"}})
    if timed_out or exit_code == 124:
        records.append({"ts": now, "type": "resource_limit",
                        "detail": {"resource": "timeout", "message": f"run hit the {timeout_seconds}s limit"}})
    for path in tampered_decoys:
        records.append({"ts": now, "type": "file_write",
                        "detail": {"path": path, "message": "decoy file modified or deleted"}})
    return records
