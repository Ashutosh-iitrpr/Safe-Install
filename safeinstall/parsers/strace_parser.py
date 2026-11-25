"""Parse strace syscall traces into normalized behavioral events."""

import ast
import re
from pathlib import Path

from safeinstall.contracts import Event


LINE_RE = re.compile(
    r"^(?P<pid>\d+)\s+(?P<ts>\d+(?:\.\d+)?)\s+(?P<syscall>\w+)\((?P<args>.*)\)\s+=\s+(?P<result>.*)$"
)
QUOTED_PATH_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')
CONNECT_PORT_RE = re.compile(r"sin_port=htons\((?P<port>\d+)\)")
SOCKADDR_INET_RE = re.compile(r'sin_addr=inet_addr\("(?P<host>[^"]+)"\)')
SOCKADDR_INET6_RE = re.compile(r'sin6_addr=inet_pton\(AF_INET6,\s*"(?P<host>[^"]+)"\)')

SYSTEM_PREFIXES = (
    "/proc/",
    "/sys/",
    "/dev/",
    "/lib/",
    "/usr/lib/",
    "/usr/share/",
    "/usr/local/lib/",
    "/etc/ld.so",
    "/etc/localtime",
    "/etc/nsswitch.conf",
    "/etc/host.conf",
    "/etc/resolv.conf",
    "/etc/hosts",
)


def _process_name(executable: str) -> str:
    return executable.rstrip("/").rsplit("/", 1)[-1] or "unknown"


def _quoted_strings(text: str) -> list[str]:
    return [ast.literal_eval(f'"{match.group(1)}"') for match in QUOTED_PATH_RE.finditer(text)]


def _is_system_path(path: str) -> bool:
    return path.startswith(SYSTEM_PREFIXES)


def _successful(result: str) -> bool:
    result = result.strip()
    return not result.startswith("-1")

UNFINISHED_RE = re.compile(
    r"^(?P<pid>\d+)\s+(?P<ts>\d+(?:\.\d+)?)\s+(?P<sys>\w+)\((?P<args>.*?)\s*<unfinished \.\.\.>$"
)
RESUMED_RE = re.compile(
    r"^(?P<pid>\d+)\s+(?P<ts>\d+(?:\.\d+)?)\s+<\.\.\. (?P<sys>\w+) resumed>(?P<rest>.*)$"
)


def merge_split_lines(text: str) -> str:
    """Join strace `<unfinished ...>` / `<... resumed>` pairs back into single lines."""
    pending: dict[tuple[str, str], tuple[str, str]] = {}
    out: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        started = UNFINISHED_RE.match(line)
        if started:
            pending[(started["pid"], started["sys"])] = (started["ts"], started["args"])
            continue
        resumed = RESUMED_RE.match(line)
        if resumed:
            begin = pending.pop((resumed["pid"], resumed["sys"]), None)
            if begin:
                out.append(f'{resumed["pid"]} {begin[0]} {resumed["sys"]}({begin[1]}{resumed["rest"]}')
            continue
        out.append(line)
    return "\n".join(out)


def parse_strace(text: str) -> list[Event]:
    """Convert strace text into normalized Event contracts."""
    events: list[Event] = []
    process_by_pid: dict[int, str] = {}
    pid_limit_seen = False

    for line in merge_split_lines(text).splitlines():
        match = LINE_RE.match(line.strip())
        if not match:
            continue

        pid = int(match.group("pid"))
        ts = float(match.group("ts"))
        syscall = match.group("syscall")
        args = match.group("args")
        result = match.group("result")

        if syscall == "execve":
            if not _successful(result):
                continue
            executable = _quoted_strings(args)[0] if _quoted_strings(args) else "unknown"
            process = _process_name(executable)
            process_by_pid[pid] = process
            cmdline: list[str] = []
            bracket = args.find("[")
            if bracket >= 0:
                depth = 0
                end = bracket
                for index in range(bracket, len(args)):
                    if args[index] == "[":
                        depth += 1
                    elif args[index] == "]":
                        depth -= 1
                        if depth == 0:
                            end = index + 1
                            break
                try:
                    cmdline = ast.literal_eval(args[bracket:end])
                except (SyntaxError, ValueError):
                    cmdline = [process]
            events.append(Event(
                ts=ts,
                source="strace",
                type="exec",
                pid=pid,
                process=process,
                detail={"cmdline": cmdline or [process]},
            ))
            continue

        process = process_by_pid.get(pid, f"pid-{pid}")
        if syscall in {"clone", "clone3", "vfork", "fork"}:
            child = result.split()[0] if result else ""
            if child.isdigit() and int(child) > 0:
                process_by_pid[int(child)] = process
            elif "EAGAIN" in result and not pid_limit_seen:
                pid_limit_seen = True
                events.append(Event(
                    ts=ts, source="strace", type="resource_limit", pid=pid, process=process,
                    detail={"resource": "pids", "message": "fork/clone failed with EAGAIN (pids limit reached)"},
                ))
            continue  
        
        if syscall == "openat" and _successful(result):
            strings = _quoted_strings(args)
            if not strings:
                continue
            path = strings[0]
            if _is_system_path(path):
                continue
            flags = args.split(",", 2)[-1].split(")", 1)[0] if "," in args else ""
            is_write = any(
                flag in flags
                for flag in ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")
            )
            events.append(Event(
                ts=ts,
                source="strace",
                type="file_write" if is_write else "file_read",
                pid=pid,
                process=process,
                detail={"path": path},
            ))
            continue

        if syscall == "connect":
            host_match = SOCKADDR_INET_RE.search(args) or SOCKADDR_INET6_RE.search(args)
            port_match = CONNECT_PORT_RE.search(args)
            if host_match and port_match:
                detail = {
                    "host": host_match.group("host"),
                    "port": int(port_match.group("port")),
                }
                if not _successful(result):
                    error_match = re.search(r"-1\s+([A-Z][A-Z0-9]*)", result)
                    if error_match:
                        detail["error"] = error_match.group(1)
                events.append(Event(
                    ts=ts,
                    source="strace",
                    type="net_connect",
                    pid=pid,
                    process=process,
                    detail=detail,
                ))
            continue

        if syscall in {"sendto", "sendmsg"} and _successful(result):
            host_match = SOCKADDR_INET_RE.search(args) or SOCKADDR_INET6_RE.search(args)
            port_match = CONNECT_PORT_RE.search(args)
            if host_match and port_match:
                events.append(Event(
                    ts=ts,
                    source="strace",
                    type="net_connect",
                    pid=pid,
                    process=process,
                    detail={
                        "host": host_match.group("host"),
                        "port": int(port_match.group("port")),
                    },
                ))
            continue

        if syscall in {"unlinkat", "rename", "renameat", "renameat2"}:
            strings = _quoted_strings(args)
            if strings:
                path = strings[-1]
                if not _is_system_path(path):
                    events.append(Event(
                        ts=ts,
                        source="strace",
                        type="file_write",
                        pid=pid,
                        process=process,
                        detail={"path": path, "operation": syscall},
                    ))
            continue

    return events


def parse_strace_file(path: str | Path) -> list[Event]:
    """Read a strace artifact and return normalized events."""
    return parse_strace(Path(path).read_text(encoding="utf-8", errors="replace"))
