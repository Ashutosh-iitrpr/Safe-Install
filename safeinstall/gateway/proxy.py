"""Small HTTP proxy for the SafeInstall gateway."""

import http.client
import hashlib
import json
import select
import socket
import socketserver
import threading
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Iterable
from urllib.parse import urlsplit


DEFAULT_REGISTRY_ALLOWLIST = frozenset({
    "pypi.org",
    "files.pythonhosted.org",
    "registry.npmjs.org",
})


def hostname(host: str) -> str:
    """Normalize a host or host:port value to a DNS-style hostname."""
    host = host.strip().lower()
    if host.startswith("["):
        return host[1:].split("]", 1)[0]
    return host.rsplit(":", 1)[0] if ":" in host else host


class GatewayProxy:
    """State for allowlist decisions and gateway JSONL logging."""

    def __init__(self, log_path: Path, allowlist: Iterable[str] = ()) -> None:
        self.log_path = log_path
        self.allowlist = frozenset(hostname(item) for item in allowlist) or DEFAULT_REGISTRY_ALLOWLIST
        self._lock = threading.Lock()

    def allowed(self, host: str) -> bool:
        return hostname(host) in self.allowlist

    def log(self, record: dict[str, object]) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            with self.log_path.open("a", encoding="utf-8") as log_file:
                log_file.write(json.dumps(record, sort_keys=True) + "\n")


class _ProxyServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    gateway: GatewayProxy


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server: _ProxyServer

    def do_GET(self) -> None:
        self._proxy_request()

    def do_POST(self) -> None:
        self._proxy_request()

    def do_PUT(self) -> None:
        self._proxy_request()

    def do_HEAD(self) -> None:
        self._proxy_request()

    def do_DELETE(self) -> None:
        self._proxy_request()

    def do_PATCH(self) -> None:
        self._proxy_request()

    def do_OPTIONS(self) -> None:
        self._proxy_request()

    def do_CONNECT(self) -> None:
        host, port = self._host_and_port()
        allowed = self.server.gateway.allowed(host)
        self.server.gateway.log({
            "type": "http_request",
            "method": "CONNECT",
            "host": host,
            "port": port,
            "allowed": allowed,
            "url": f"{host}:{port}",
        })

        if not allowed:
            self.send_error(403, "Host not allowlisted")
            return

        try:
            upstream = socket.create_connection((host, port), timeout=10)
        except OSError as exc:
            self.send_error(502, str(exc))
            return

        self.send_response(200, "Connection Established")
        self.end_headers()
        upstream.setblocking(False)
        self.connection.setblocking(False)
        while True:
            readable, _, _ = select.select([self.connection, upstream], [], [], 30)
            if not readable:
                break
            if self.connection in readable:
                data = self.connection.recv(65536)
                if not data:
                    break
                upstream.sendall(data)
            if upstream in readable:
                data = upstream.recv(65536)
                if not data:
                    break
                self.connection.sendall(data)
        upstream.close()

    def _host_and_port(self) -> tuple[str, int]:
        target = urlsplit(f"//{self.path}", scheme="http")
        host = target.hostname or hostname(self.headers.get("Host", ""))
        port = target.port or (443 if self.command == "CONNECT" else 80)
        return host, port

    def _proxy_request(self) -> None:
        target = urlsplit(self.path)
        if target.hostname:
            host = target.hostname
            port = target.port or (443 if target.scheme == "https" else 80)
            path = target.path or "/"
            if target.query:
                path += "?" + target.query
        else:
            host, port = self._host_and_port()
            path = self.path

        body = self._request_body()
        allowed = self.server.gateway.allowed(host)
        body_excerpt = body[:1024].decode("utf-8", "replace")
        self.server.gateway.log({
            "type": "http_request",
            "method": self.command,
            "host": host,
            "port": port,
            "allowed": allowed,
            "url": self.path,
            "body_excerpt": body_excerpt,
            "body_length": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "headers": {
                "content-type": self.headers.get("Content-Type", ""),
                "user-agent": self.headers.get("User-Agent", ""),
            },
        })

        if not allowed:
            self.send_response(200)
            sinkhole_body = b"SafeInstall sinkhole: request recorded\n"
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(sinkhole_body)))
            self.send_header("X-SafeInstall-Sinkhole", "1")
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(sinkhole_body)
            return

        try:
            connection = http.client.HTTPConnection(host, port, timeout=10)
            forwarded_headers = dict(self.headers)
            forwarded_headers.pop("Proxy-Authorization", None)
            connection.request(self.command, path, body=body, headers=forwarded_headers)
            response = connection.getresponse()
            data = response.read()
            self.send_response(response.status, response.reason)
            for key, value in response.getheaders():
                if key.lower() not in {"transfer-encoding", "connection"}:
                    self.send_header(key, value)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)
            connection.close()
        except OSError as exc:
            self.send_error(502, str(exc))

    def _request_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0"))
        return self.rfile.read(length) if length else b""

    def log_message(self, format: str, *args: object) -> None:
        return


def serve_proxy(host: str, port: int, log_path: Path, allowlist: Iterable[str] = ()) -> _ProxyServer:
    """Create and bind a gateway proxy server without starting its loop."""
    server = _ProxyServer((host, port), ProxyHandler)
    server.gateway = GatewayProxy(log_path, allowlist)
    return server


def main() -> None:
    import argparse
    import os

    parser = argparse.ArgumentParser(description="SafeInstall gateway proxy")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=int(os.getenv("SAFEINSTALL_PROXY_PORT", "3128")))
    parser.add_argument(
        "--log",
        type=Path,
        default=Path(os.getenv("SAFEINSTALL_GATEWAY_LOG", "/work/gateway.jsonl")),
    )
    args = parser.parse_args()

    server = serve_proxy(args.host, args.port, args.log)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
