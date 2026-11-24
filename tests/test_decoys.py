"""Tests for harmless decoy generation."""

import json
import subprocess
from pathlib import Path

from safeinstall.sandbox.make_decoys import generate_decoys


def test_generate_decoys_creates_distinct_canaries(tmp_path) -> None:
    home = tmp_path / "home"
    manifest = tmp_path / "run" / "canaries.json"

    entries = generate_decoys(home, manifest)

    assert len(entries) == 3
    assert len({entry["token"] for entry in entries}) == 3
    assert json.loads(manifest.read_text()) == entries

    for entry in entries:
        path = tmp_path / "home" / entry["kind"]
        assert path == tmp_path / "home" / entry["kind"]
        assert entry["token"] in path.read_text()
        assert path.stat().st_mode & 0o777 == 0o600


def test_entrypoint_shell_syntax() -> None:
    entrypoint = "safeinstall/sandbox/entrypoint.sh"
    subprocess.run(["sh", "-n", entrypoint], check=True)


def test_npm_smoke_passes_module_to_node() -> None:
    entrypoint = Path("safeinstall/sandbox/entrypoint.sh").read_text()

    assert 'node -e "require(process.argv[1])" "$2"' in entrypoint
