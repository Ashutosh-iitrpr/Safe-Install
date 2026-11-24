"""Tests for run directory lifecycle and cleanup behavior."""

import tempfile
from pathlib import Path

from safeinstall.orchestrator import NetworkTopology, Orchestrator


class FakeContainer:
    def __init__(self) -> None:
        self.removed = False
        self.reloaded = False
        self.attrs = {
            "NetworkSettings": {
                "Networks": {
                    "test-internal": {"IPAddress": "172.18.0.3"},
                }
            }
        }

    def wait(self, timeout: int) -> dict[str, int]:
        return {"StatusCode": 0}

    def reload(self) -> None:
        self.reloaded = True

    def stats(self, stream: bool) -> dict[str, object]:
        return {"memory_stats": {"usage": 1234, "max_usage": 2345}}

    def diff(self) -> list[dict[str, object]]:
        return [{"Kind": 1, "Path": "/work/test"}]

    def logs(self) -> bytes:
        return b"fake logs"

    def remove(self, force: bool) -> None:
        self.removed = True


class FakeNetwork:
    def __init__(self) -> None:
        self.removed = False
        self.gateway = None

    def connect(self, gateway: FakeContainer) -> None:
        self.gateway = gateway

    def remove(self) -> None:
        self.removed = True


class FakeNetworks:
    def __init__(self) -> None:
        self.network = FakeNetwork()

    def create(self, name: str, internal: bool) -> FakeNetwork:
        assert internal is True
        return self.network


class FakeContainers:
    def __init__(self) -> None:
        self.items: list[FakeContainer] = []

    def run(self, *args: object, **kwargs: object) -> FakeContainer:
        container = FakeContainer()
        container.attrs["NetworkSettings"]["Networks"] = {
            kwargs.get("name", "test-internal"): {"IPAddress": "172.18.0.3"}
        }
        if kwargs.get("name", "").startswith("safeinstall-gateway"):
            container.attrs["NetworkSettings"]["Networks"] = {
                "test-internal": {"IPAddress": "172.18.0.2"}
            }
        self.items.append(container)
        return container


class FakeClient:
    def __init__(self) -> None:
        self.networks = FakeNetworks()
        self.containers = FakeContainers()


def test_network_topology() -> None:
    topology = NetworkTopology("network", "gateway", "sandbox")
    assert topology.sandbox_networks() == ("network",)
    assert topology.gateway_networks() == ("bridge", "network")


def test_orchestrator_creates_meta_and_cleans_up() -> None:
    with tempfile.TemporaryDirectory() as directory:
        client = FakeClient()
        orchestrator = Orchestrator(
            runs_root=Path(directory),
            docker_client=client,
        )

        result = orchestrator.run("pip", "/src/clean-pkg")

        assert result.exit_code == 0
        assert (result.run_dir / "meta.json").exists()
        assert (result.run_dir / "fsdiff.txt").read_text() == "A /work/test\n"
        meta = __import__("json").loads((result.run_dir / "meta.json").read_text())
        assert meta["peak_mem"] == 2345
        assert meta["exit_code"] == 0
        assert client.networks.network.removed is True
        assert all(container.removed for container in client.containers.items)
