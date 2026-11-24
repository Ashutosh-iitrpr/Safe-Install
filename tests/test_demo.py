import json
import importlib.util
import subprocess
import sys
import threading
from http.client import HTTPConnection
from pathlib import Path



def _create_sink_server():
    module_path = Path("demo/sink/server.py").resolve()
    spec = importlib.util.spec_from_file_location("safeinstall_demo_sink", module_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.create_server


def test_clean_demo_package_is_side_effect_free() -> None:
    package_dir = Path("demo/clean-pkg")
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from clean_pkg import greet; assert greet('tester') == 'Hello, tester!'",
        ],
        cwd=package_dir,
        check=True,
    )

    assert result.returncode == 0


def test_sink_records_post_body(tmp_path: Path) -> None:
    log_path = tmp_path / "sink.jsonl"
    create_server = _create_sink_server()
    server = create_server("127.0.0.1", 0, log_path)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        connection = HTTPConnection("127.0.0.1", server.server_port)
        connection.request("POST", "/upload", body=b"demo-body")
        response = connection.getresponse()
        assert response.status == 200
        response.read()
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)

    record = json.loads(log_path.read_text().strip())
    assert record["method"] == "POST"
    assert record["path"] == "/upload"
    assert record["body_excerpt"] == "demo-body"
    assert record["body_length"] == len(b"demo-body")
