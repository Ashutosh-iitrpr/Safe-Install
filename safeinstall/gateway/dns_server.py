"""UDP DNS sink server that records every query in the gateway JSONL."""

import json
import socket
import struct
import threading
from pathlib import Path


def parse_question(data: bytes) -> tuple[str, int] | None:
    if len(data) < 12:
        return None
    offset = 12
    labels: list[str] = []
    while offset < len(data):
        length = data[offset]
        offset += 1
        if length == 0:
            break
        if length & 0xC0:
            return None
        if offset + length > len(data):
            return None
        labels.append(data[offset:offset + length].decode("ascii", "replace"))
        offset += length
    if offset + 4 > len(data):
        return None
    query_type = struct.unpack("!H", data[offset:offset + 2])[0]
    return ".".join(labels).lower().rstrip("."), query_type


def dns_response(data: bytes, name: str, query_type: int) -> bytes:
    del name
    transaction_id = data[:2]
    answer_count = 1 if query_type == 1 else 0
    header = struct.pack(
        "!HHHHHH",
        int.from_bytes(transaction_id, "big"),
        0x8180,
        1,
        answer_count,
        0,
        0,
    )
    question_end = 12
    while question_end < len(data):
        length = data[question_end]
        question_end += 1
        if length == 0:
            break
        question_end += length
    question_end += 4
    question = data[12:question_end]
    if not answer_count:
        return header + question
    answer = (
        b"\xc0\x0c"
        + struct.pack("!HHIH", 1, 1, 60, 4)
        + socket.inet_aton("10.255.0.1")
    )
    return header + question + answer


class DNSLogger:
    def __init__(self, log_path: Path, host: str = "0.0.0.0", port: int = 53) -> None:
        self.log_path = log_path
        self.host = host
        self.port = port
        self._socket: socket.socket | None = None
        self._thread: threading.Thread | None = None

    def _log(self, record: dict[str, object]) -> None:
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        with self.log_path.open("a", encoding="utf-8") as log_file:
            log_file.write(json.dumps(record, sort_keys=True) + "\n")

    def start(self) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self.host, self.port))
        sock.settimeout(0.5)
        self._socket = sock
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._socket:
            self._socket.close()
        if self._thread:
            self._thread.join(timeout=1)

    def _serve(self) -> None:
        assert self._socket is not None
        while True:
            try:
                data, address = self._socket.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            parsed = parse_question(data)
            if parsed is None:
                continue
            name, query_type = parsed
            self._log({
                "type": "dns",
                "host": name,
                "query_type": query_type,
                "source": f"{address[0]}:{address[1]}",
            })
            response = dns_response(data, name, query_type)
            try:
                self._socket.sendto(response, address)
            except OSError:
                return


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="SafeInstall DNS query logger")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=53)
    parser.add_argument("--log", type=Path, default=Path("/work/gateway.jsonl"))
    args = parser.parse_args()

    logger = DNSLogger(args.log, args.host, args.port)
    logger.start()
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        logger.stop()


if __name__ == "__main__":
    main()
