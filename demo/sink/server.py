#!/usr/bin/env python3
"""Harmless local HTTP sink that records request metadata and POST bodies."""

import argparse
import hashlib
import json
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class SinkHandler(BaseHTTPRequestHandler):
    """Record requests as JSON Lines and return a successful response."""

    server_version = "SafeInstallSink/1.0"

    def do_GET(self) -> None:
        self._write_record(b"")
        self._respond()

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        self._write_record(self.rfile.read(length))
        self._respond()

    def log_message(self, format: str, *args: object) -> None:
        return

    def _write_record(self, body: bytes) -> None:
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": self.command,
            "path": self.path,
            "body_excerpt": body[:4096].decode("utf-8", "replace"),
            "body_length": len(body),
            "body_sha256": hashlib.sha256(body).hexdigest(),
            "client": self.client_address[0],
        }
        log_path = self.server.log_path  # type: ignore[attr-defined]
        with log_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(record, sort_keys=True) + "\n")

    def _respond(self) -> None:
        response = b"SafeInstall demo sink recorded request\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)


def serve(host: str, port: int, log_path: Path) -> None:
    """Serve the sink until interrupted."""
    server = create_server(host, port, log_path)
    print(f"SafeInstall sink listening on http://{host}:{port}", flush=True)
    server.serve_forever()


def create_server(host: str, port: int, log_path: Path) -> ThreadingHTTPServer:
    """Create a configured sink server for embedding or testing."""
    log_path.parent.mkdir(parents=True, exist_ok=True)
    server = ThreadingHTTPServer((host, port), SinkHandler)
    server.log_path = log_path  # type: ignore[attr-defined]
    return server


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--log", type=Path, default=Path("sink.jsonl"))
    args = parser.parse_args()
    serve(args.host, args.port, args.log)


if __name__ == "__main__":
    main()
