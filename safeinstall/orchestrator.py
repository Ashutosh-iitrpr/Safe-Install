"""Sandbox lifecycle orchestration."""

import json
import secrets
import time
from datetime import datetime, timezone
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import docker

from .config import SandboxLimits, gateway_environment, sandbox_container_kwargs


@dataclass(frozen=True)
class NetworkTopology:
    """Docker network attachment plan for one SafeInstall run."""

    internal_name: str
    gateway_name: str
    sandbox_name: str

    def validate(self) -> None:
        if not self.internal_name:
            raise ValueError("internal_name must not be empty")
        if self.gateway_name == self.sandbox_name:
            raise ValueError("gateway and sandbox container names must differ")

    def sandbox_networks(self) -> tuple[str, ...]:
        """The sandbox receives only the internal, non-egress network."""
        return (self.internal_name,)

    def gateway_networks(self) -> tuple[str, ...]:
        """The gateway bridges the internal network and the host network."""
        return ("bridge", self.internal_name)


@dataclass(frozen=True)
class RunResult:
    """Paths and status produced by one orchestrated run."""

    run_id: str
    run_dir: Path
    exit_code: int
    timed_out: bool


class Orchestrator:
    """Create, run, collect, and always clean up a SafeInstall sandbox."""

    def __init__(
        self,
        runs_root: Path | None = None,
        docker_client: Any | None = None,
        sandbox_image: str = "safeinstall-sandbox:test",
        gateway_image: str = "safeinstall-gateway:test",
    ) -> None:
        self.runs_root = Path(runs_root) if runs_root is not None else Path("runs")
        self.client = docker_client or docker.from_env()
        self.sandbox_image = sandbox_image
        self.gateway_image = gateway_image

    def run(
        self,
        ecosystem: str,
        target: str,
        smoke_module: str | None = None,
        limits: SandboxLimits | None = None,
    ) -> RunResult:
        limits = limits or SandboxLimits()
        if ecosystem not in {"pip", "npm"}:
            raise ValueError("ecosystem must be 'pip' or 'npm'")

        run_id = f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}-{secrets.token_hex(4)}"
        run_dir = self.runs_root.resolve() / run_id
        run_dir.mkdir(parents=True, exist_ok=True)
        meta_path = run_dir / "meta.json"
        network = None
        gateway = None
        sandbox = None
        timed_out = False
        exit_code = 1
        started_at = datetime.now(timezone.utc).isoformat()
        peak_mem = None

        self._write_meta(
            meta_path,
            {
                "input": target,
                "resolved_version": None,
                "started_at": started_at,
                "limits": {
                    "timeout_seconds": limits.timeout_seconds,
                    "memory_bytes": limits.memory_bytes,
                    "nano_cpus": limits.nano_cpus,
                    "pids_limit": limits.pids_limit,
                },
                "exit_code": None,
                "peak_mem": None,
            },
        )

        try:
            topology = NetworkTopology(
                internal_name=f"safeinstall-{run_id}",
                gateway_name=f"safeinstall-gateway-{run_id}",
                sandbox_name=f"safeinstall-sandbox-{run_id}",
            )
            topology.validate()
            network = self.client.networks.create(topology.internal_name, internal=True)

            gateway = self.client.containers.run(
                self.gateway_image,
                command=[
                    "/opt/safeinstall/proxy.py",
                    "--host",
                    "0.0.0.0",
                    "--port",
                    "3128",
                    "--log",
                    "/work/gateway.jsonl",
                ],
                entrypoint="python",
                name=topology.gateway_name,
                detach=True,
                network="bridge",
                volumes={str(run_dir): {"bind": "/work", "mode": "rw"}},
            )
            network.connect(gateway)

            gateway_networks = gateway.attrs["NetworkSettings"]["Networks"]
            gateway_ip = gateway_networks.get(topology.internal_name)
            if gateway_ip:
                gateway_ip = gateway_ip["IPAddress"]
            else:
                gateway_ip = next(iter(gateway_networks.values()))["IPAddress"]
            environment = gateway_environment(f"http://{gateway_ip}:3128")

            sandbox_kwargs = sandbox_container_kwargs(self.sandbox_image, limits)
            sandbox_kwargs["read_only"] = True
            sandbox_kwargs["tmpfs"] = {
                key: value
                for key, value in sandbox_kwargs["tmpfs"].items()
                if key != "/work"
            }
            sandbox_kwargs["name"] = topology.sandbox_name
            sandbox_kwargs["detach"] = True
            sandbox_kwargs["network"] = topology.internal_name
            sandbox_kwargs["environment"] = {
                **environment,
                "SAFEINSTALL_PROXY_URL": f"http://{gateway_ip}:3128",
                "SAFEINSTALL_TIMEOUT": str(limits.timeout_seconds),
            }
            sandbox_kwargs["volumes"] = {str(run_dir): {"bind": "/work", "mode": "rw"}}

            sandbox_target = target
            host_target = Path(target).expanduser()
            if host_target.exists():
                source_dir = host_target.resolve()
                sandbox_target = "/src"
                sandbox_kwargs["volumes"][str(source_dir)] = {
                    "bind": "/src",
                    "mode": "rw",
                }

            sandbox_kwargs["command"] = [
                "--timeout",
                str(limits.timeout_seconds),
                ecosystem,
                sandbox_target,
            ]
            if smoke_module:
                sandbox_kwargs["command"].append(smoke_module)

            sandbox = self.client.containers.run(**sandbox_kwargs)
            started = time.monotonic()
            try:
                wait_result = sandbox.wait(timeout=limits.timeout_seconds)
                exit_code = int(wait_result.get("StatusCode", 1))
            except Exception as exc:
                if "timeout" not in str(exc).lower():
                    raise
                timed_out = True
                sandbox.kill()
                exit_code = 124

            elapsed = time.monotonic() - started
            if elapsed >= limits.timeout_seconds:
                timed_out = timed_out or exit_code == 124

            try:
                (run_dir / "sandbox.log").write_bytes(sandbox.logs())
            except Exception:
                pass
            try:
                (run_dir / "gateway.log").write_bytes(gateway.logs())
            except Exception:
                pass

            try:
                stats = sandbox.stats(stream=False)
                peak_mem = int(stats["memory_stats"].get("usage", 0))
            except Exception:
                peak_mem = None

            (run_dir / "fsdiff.txt").write_text(
                self._docker_diff(sandbox),
                encoding="utf-8",
            )
        except Exception as exc:
            if timed_out:
                raise
            exit_code = 1
            (run_dir / "orchestrator-error.txt").write_text(str(exc), encoding="utf-8")
        finally:
            for container in (sandbox, gateway):
                if container is not None:
                    try:
                        container.remove(force=True)
                    except Exception:
                        pass
            if network is not None:
                try:
                    network.remove()
                except Exception:
                    pass

        self._write_meta(
            meta_path,
            {
                "input": target,
                "resolved_version": None,
                "started_at": started_at,
                "finished_at": datetime.now(timezone.utc).isoformat(),
                "limits": {
                    "timeout_seconds": limits.timeout_seconds,
                    "memory_bytes": limits.memory_bytes,
                    "nano_cpus": limits.nano_cpus,
                    "pids_limit": limits.pids_limit,
                },
                "exit_code": exit_code,
                "peak_mem": locals().get("peak_mem"),
            },
        )

        return RunResult(
            run_id=run_id,
            run_dir=run_dir,
            exit_code=exit_code,
            timed_out=timed_out,
        )

    def _docker_diff(self, sandbox: Any) -> str:
        try:
            changes = sandbox.diff()
            return "\n".join(
                f"{change['Kind']} {change['Path']}"
                for change in changes
            ) + ("\n" if changes else "")
        except Exception:
            return ""

    @staticmethod
    def _write_meta(path: Path, data: dict[str, Any]) -> None:
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
