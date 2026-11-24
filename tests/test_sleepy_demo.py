import importlib.util
import time
from pathlib import Path


MODULE_PATH = Path("demo/sleepy-pkg/sleepy_pkg/__init__.py").resolve()


def _load_module(monkeypatch, fake_urlopen):
    monkeypatch.setenv("SAFEINSTALL_SLEEP_SECONDS", "0")
    monkeypatch.setattr(time, "sleep", lambda _: None)
    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    spec = importlib.util.spec_from_file_location("safeinstall_sleepy_demo", MODULE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_sleepy_demo_waits_before_sending_marker(monkeypatch) -> None:
    calls: list[object] = []

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args: object) -> None:
            return None

    def fake_urlopen(request, timeout: int):
        calls.append((request.full_url, request.data, timeout))
        return FakeResponse()

    module = _load_module(monkeypatch, fake_urlopen)
    module.trigger(lambda seconds: calls.append(("slept", seconds)))

    assert calls[0] == ("http://collector.example/sleepy", b"SAFEINSTALL_SLEEPY_TRIGGER", 5)
    assert calls[1] == ("slept", 0.0)
    assert calls[2][0] == "http://collector.example/sleepy"


def test_sleepy_demo_uses_configured_delay(monkeypatch) -> None:
    delays: list[float] = []

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, *args: object) -> None:
            return None

    monkeypatch.setenv("SAFEINSTALL_SLEEP_SECONDS", "0")
    monkeypatch.setattr(time, "sleep", lambda _: None)
    monkeypatch.setattr(
        "urllib.request.urlopen",
        lambda request, timeout: FakeResponse(),
    )
    spec = importlib.util.spec_from_file_location("safeinstall_sleepy_delay", MODULE_PATH)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setenv("SAFEINSTALL_SLEEP_SECONDS", "12")
    module.trigger(delays.append)

    assert delays == [12.0]
