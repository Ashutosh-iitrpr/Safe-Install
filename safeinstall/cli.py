"""Command-line entry point for SafeInstall."""

from pathlib import Path

import typer

from .config import SandboxLimits
from .orchestrator import Orchestrator


app = typer.Typer(
    name="safeinstall",
    help="Run package installs in a disposable security sandbox.",
    no_args_is_help=True,
)


def _run(ecosystem: str, target: str, smoke: str | None, timeout: int) -> None:
    if timeout < 1:
        raise typer.BadParameter("timeout must be at least 1 second")

    typer.echo(f"Running {ecosystem} target: {target}")
    try:
        result = Orchestrator(runs_root=Path("runs")).run(
            ecosystem=ecosystem,
            target=target,
            smoke_module=smoke,
            limits=SandboxLimits(timeout_seconds=timeout),
        )
    except Exception as exc:
        typer.echo(f"SafeInstall could not start the run: {exc}", err=True)
        raise typer.Exit(code=2) from exc

    typer.echo(f"Run artifacts: {result.run_dir}")
    if result.timed_out:
        typer.echo("Observation window timed out.", err=True)
        raise typer.Exit(code=1)

    if result.exit_code != 0:
        typer.echo(f"Sandbox process exited with code {result.exit_code}.", err=True)
        raise typer.Exit(code=1)


@app.command("pip")
def pip_command(
    target: str = typer.Argument(..., help="Package name, version, or local package path"),
    smoke: str | None = typer.Option(None, "--smoke", help="Python module for the import smoke test"),
    timeout: int = typer.Option(120, "--timeout", min=1, help="Maximum observation seconds"),
) -> None:
    """Run a pip package in the SafeInstall sandbox."""
    _run("pip", target, smoke, timeout)


@app.command("npm")
def npm_command(
    target: str = typer.Argument(..., help="npm package name or local package path"),
    smoke: str | None = typer.Option(None, "--smoke", help="Node module for the require smoke test"),
    timeout: int = typer.Option(120, "--timeout", min=1, help="Maximum observation seconds"),
) -> None:
    """Run an npm package in the SafeInstall sandbox."""
    _run("npm", target, smoke, timeout)
