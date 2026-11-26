"""Controlled PID-limit fixture for SafeInstall RESOURCE_ABUSE detection."""

import subprocess


TARGET_PROCS = 300


def trigger() -> None:
    """Spawn short-lived sleep processes until hitting the 256 PIDs limit."""
    procs: list[subprocess.Popen[bytes]] = []
    try:
        for _ in range(TARGET_PROCS):
            procs.append(subprocess.Popen(["sleep", "2"]))
    except OSError:
        # Expected once cgroup pids_limit (256) rejects fork/clone with EAGAIN.
        pass
    finally:
        for proc in procs:
            try:
                proc.wait(timeout=5)
            except Exception:
                pass


trigger()
