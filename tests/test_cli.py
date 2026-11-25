"""Tests for the SafeInstall Typer commands."""

import json
from pathlib import Path

from typer.testing import CliRunner

from safeinstall import cli
from safeinstall.contracts import Verdict
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


def test_json_output_is_machine_readable(monkeypatch, tmp_path) -> None:
    class FakeOrchestrator:
        def __init__(self, runs_root: Path) -> None:
            pass

        def run(self, **kwargs: object) -> RunResult:
            return RunResult(
                run_id="json-run",
                run_dir=tmp_path / "json-run",
                exit_code=0,
                timed_out=False,
                verdict=Verdict.NO_SUSPICIOUS_BEHAVIOR_OBSERVED,
            )

    monkeypatch.setattr(cli, "Orchestrator", FakeOrchestrator)

    result = runner.invoke(cli.app, ["pip", "requests", "--json"])
    payload = json.loads(result.stdout)

    assert result.exit_code == 0
    assert payload["run_id"] == "json-run"
    assert payload["verdict"] == "NO SUSPICIOUS BEHAVIOR OBSERVED"
    assert payload["exit_code"] == 0
    assert "Running pip" not in result.stdout


def test_verdict_exit_codes() -> None:
    assert cli.cli_exit_code(Verdict.NO_SUSPICIOUS_BEHAVIOR_OBSERVED) == 0
    assert cli.cli_exit_code(Verdict.WARNING) == 1
    assert cli.cli_exit_code(Verdict.BLOCK) == 2
    assert cli.cli_exit_code(None, sandbox_exit_code=1) == 3
    assert cli.cli_exit_code(Verdict.BLOCK, sandbox_exit_code=1) == 2
    assert cli.cli_exit_code(Verdict.BLOCK, timed_out=True) == 2
    assert cli.cli_exit_code(Verdict.INCONCLUSIVE) == 3