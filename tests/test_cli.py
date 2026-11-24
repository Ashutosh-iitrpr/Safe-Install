"""Tests for the SafeInstall Typer commands."""

from pathlib import Path

from typer.testing import CliRunner

from safeinstall import cli
from safeinstall.orchestrator import RunResult


runner = CliRunner()


def test_pip_command_runs_orchestrator(monkeypatch, tmp_path) -> None:
    captured: dict[str, object] = {}

    class FakeOrchestrator:
        def __init__(self, runs_root: Path) -> None:
            assert runs_root == Path("runs")

        def run(self, **kwargs: object) -> RunResult:
            captured.update(kwargs)
            return RunResult(
                run_id="test-run",
                run_dir=tmp_path / "test-run",
                exit_code=0,
                timed_out=False,
            )

    monkeypatch.setattr(cli, "Orchestrator", FakeOrchestrator)

    result = runner.invoke(cli.app, ["pip", "requests==2.32.0", "--timeout", "30"])

    assert result.exit_code == 0
    assert "Running pip target: requests==2.32.0" in result.stdout
    assert captured["ecosystem"] == "pip"
    assert captured["target"] == "requests==2.32.0"
    assert captured["limits"].timeout_seconds == 30


def test_npm_command_runs_orchestrator(monkeypatch, tmp_path) -> None:
    class FakeOrchestrator:
        def __init__(self, runs_root: Path) -> None:
            pass

        def run(self, **kwargs: object) -> RunResult:
            return RunResult(
                run_id="test-run",
                run_dir=tmp_path / "test-run",
                exit_code=0,
                timed_out=False,
            )

    monkeypatch.setattr(cli, "Orchestrator", FakeOrchestrator)

    result = runner.invoke(cli.app, ["npm", "left-pad", "--smoke", "left-pad"])

    assert result.exit_code == 0
    assert "Running npm target: left-pad" in result.stdout
