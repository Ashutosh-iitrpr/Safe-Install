"""End-to-end tests through real Docker. Run with: make build && pytest -m docker"""

import json
from pathlib import Path

import pytest

from safeinstall.contracts import Verdict

pytestmark = pytest.mark.docker
DEMO = Path(__file__).resolve().parents[1] / "demo"


@pytest.fixture(scope="module")
def orchestrator(tmp_path_factory):
    docker = pytest.importorskip("docker")
    try:
        client = docker.from_env()
        client.ping()
        client.images.get("safeinstall-sandbox:test")
        client.images.get("safeinstall-gateway:test")
    except Exception as exc:  # daemon down or images not built
        pytest.skip(f"Docker or images unavailable: {exc}")
    from safeinstall.orchestrator import Orchestrator

    return Orchestrator(runs_root=tmp_path_factory.mktemp("runs"), docker_client=client)


def _rule_ids(result) -> set[str]:
    findings = json.loads((result.run_dir / "findings.json").read_text(encoding="utf-8"))
    return {finding["rule_id"] for finding in findings}


def test_evil_pkg_is_blocked(orchestrator):
    result = orchestrator.run("pip", str(DEMO / "evil-pkg"))
    assert result.verdict is Verdict.BLOCK
    assert {"DECOY_READ", "CANARY_EXFIL"} <= _rule_ids(result)


def test_clean_pkg_is_clean(orchestrator):
    result = orchestrator.run("pip", str(DEMO / "clean-pkg"))
    assert result.verdict is Verdict.NO_SUSPICIOUS_BEHAVIOR_OBSERVED


def test_dns_pkg_is_flagged_via_dns_sink(orchestrator):
    result = orchestrator.run("pip", str(DEMO / "dns-pkg"))
    assert result.verdict is Verdict.WARNING
    assert "UNKNOWN_NET" in _rule_ids(result)


def test_unknown_package_is_inconclusive(orchestrator):
    result = orchestrator.run("pip", "safeinstall-no-such-package-xyz-123")
    assert result.verdict is Verdict.INCONCLUSIVE
