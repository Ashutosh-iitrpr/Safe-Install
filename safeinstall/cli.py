"""Command-line entry point for SafeInstall."""

import json
from pathlib import Path

import typer

from .config import SandboxLimits
from .contracts import Verdict
from .orchestrator import Orchestrator, RunResult
from .report.render import render_terminal


app = typer.Typer(
    name="safeinstall",
    help="Run package installs in a disposable security sandbox.",
    no_args_is_help=True,
)


def cli_exit_code(
    verdict: Verdict | None,
    sandbox_exit_code: int = 0,
    timed_out: bool = False,
) -> int:
    """Map a run result to the stable SafeInstall CLI exit-code contract."""
    if timed_out or sandbox_exit_code != 0:
        return 1
    if verdict is Verdict.BLOCK:
        return 2
    if verdict is Verdict.WARNING:
        return 1
    return 0


def _json_result(result: RunResult, cli_code: int) -> str:
    return json.dumps(
        {
            "run_id": result.run_id,
            "run_dir": str(result.run_dir),
            "sandbox_exit_code": result.exit_code,
            "timed_out": result.timed_out,
            "verdict": result.verdict.value if result.verdict else None,
            "exit_code": cli_code,
        },
        sort_keys=True,
    )


def _run(
    ecosystem: str,
    target: str,
    smoke: str | None,
    timeout: int,
    json_output: bool = False,
) -> None:
    if timeout < 1:
        raise typer.BadParameter("timeout must be at least 1 second")

    if not json_output:
        typer.echo(f"Running {ecosystem} target: {target}")
    try:
        result = Orchestrator(runs_root=Path("runs")).run(
            ecosystem=ecosystem,
            target=target,
            smoke_module=smoke,
            limits=SandboxLimits(timeout_seconds=timeout),
        )
    except Exception as exc:
        if json_output:
            typer.echo(json.dumps({"error": str(exc), "exit_code": 2}, sort_keys=True))
        else:
            typer.echo(f"SafeInstall could not start the run: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    code = cli_exit_code(result.verdict, result.exit_code, result.timed_out)
    if json_output:
        typer.echo(_json_result(result, code))
    else:
        typer.echo(f"Run artifacts: {result.run_dir}")
        report_path = result.run_dir / "report.json"
        if report_path.exists():
            from .contracts import RunArtifacts

            artifacts = RunArtifacts.model_validate_json(
                report_path.read_text(encoding="utf-8")
            )
            render_terminal(artifacts)
    if result.timed_out and not json_output:
        typer.echo("Observation window timed out.", err=True)
    elif result.exit_code != 0 and not json_output:
        typer.echo(f"Sandbox process exited with code {result.exit_code}.", err=True)
    if code:
        raise typer.Exit(code=code)


@app.command("pip")
def pip_command(
    target: str = typer.Argument(..., help="Package name, version, or local package path"),
    smoke: str | None = typer.Option(None, "--smoke", help="Python module for the import smoke test"),
    timeout: int = typer.Option(120, "--timeout", min=1, help="Maximum observation seconds"),
    json_output: bool = typer.Option(False, "--json", help="Print the result as JSON"),
) -> None:
    """Run a pip package in the SafeInstall sandbox."""
    _run("pip", target, smoke, timeout, json_output)


@app.command("npm")
def npm_command(
    target: str = typer.Argument(..., help="npm package name or local package path"),
    smoke: str | None = typer.Option(None, "--smoke", help="Node module for the require smoke test"),
    timeout: int = typer.Option(120, "--timeout", min=1, help="Maximum observation seconds"),
    json_output: bool = typer.Option(False, "--json", help="Print the result as JSON"),
) -> None:
    """Run an npm package in the SafeInstall sandbox."""
    _run("npm", target, smoke, timeout, json_output)
