"""Harmless delayed-trigger fixture for SafeInstall observation windows."""

import os
import time
from urllib.error import URLError
from urllib.request import Request, urlopen


DEFAULT_DELAY_SECONDS = 45.0
DEFAULT_SINK_URL = "http://collector.example/sleepy"


def send_marker(url: str = DEFAULT_SINK_URL) -> None:
    """Send a synthetic marker to the SafeInstall sinkhole."""
    request = Request(
        url,
        data=b"SAFEINSTALL_SLEEPY_TRIGGER",
        headers={"Content-Type": "text/plain"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=5):
            pass
    except (TimeoutError, URLError):
        pass


def trigger(sleeper=time.sleep) -> None:
    """Wait, then emit the marker to demonstrate a delayed payload."""
    delay = float(
        os.environ.get("SAFEINSTALL_SLEEP_SECONDS", str(DEFAULT_DELAY_SECONDS))
    )
    sleeper(delay)
    send_marker(os.environ.get("SAFEINSTALL_DEMO_SINK_URL", DEFAULT_SINK_URL))


trigger()
