import base64
import json
import os
from pathlib import Path

from safeinstall import runplan
from safeinstall.runplan import (
    canary_env, decoy_tamper_paths, is_local_target, make_canaries,
    orchestrator_events, pinned_requirements, pip_report_from_log, safe_copy,
)


def test_is_local_target_is_explicit():
    for local in ("./demo/evil-pkg", "../x", "/abs/path", "~/code/pkg", "sub/dir"):
        assert is_local_target(local), local
    for package in ("requests", "requests==2.32.3", "left-pad@1.3.0", "@scope/pkg",
                    "git+https://github.com/a/b", "https://example.com/p.tar.gz"):
        assert not is_local_target(package), package


def test_canaries_are_unique_realistic_and_cover_files_and_env():
    first, second = make_canaries(), make_canaries()
    tokens = [e["token"] for e in first]
    assert len(set(tokens)) == len(tokens)
    assert not set(tokens) & {e["token"] for e in second}
    assert all("SAFEINSTALL" not in t.upper() for t in tokens)
    kinds = {e["kind"] for e in first}
    assert {".env", ".ssh/id_rsa", ".aws/credentials", "env:GITHUB_TOKEN"} <= kinds


def test_canary_env_splits_env_vars_from_file_tokens():
    entries = make_canaries()
    env = canary_env(entries)
    assert env["GITHUB_TOKEN"].startswith("ghp_")
    files = json.loads(env["SAFEINSTALL_CANARIES"])
    assert ".env" in files and "GITHUB_TOKEN" not in files


def test_safe_copy_refuses_symlinks(tmp_path: Path):
    real = tmp_path / "real.log"
    real.write_text("data")
    link = tmp_path / "link.log"
    link.symlink_to(real)
    assert safe_copy(real, tmp_path / "out1")
    assert not safe_copy(link, tmp_path / "out2")
    assert not (tmp_path / "out2").exists()
    assert not safe_copy(tmp_path / "missing", tmp_path / "out3")


def test_decoy_tamper_detection():
    log = "\n".join([
        "SAFEINSTALL_DECOY_START aaa /home/sandbox/.env",
        "SAFEINSTALL_DECOY_START bbb /home/sandbox/.ssh/id_rsa",
        "SAFEINSTALL_DECOY_START ccc /home/sandbox/.npmrc",
        "pip noise",
        "SAFEINSTALL_DECOY_END aaa /home/sandbox/.env",
        "SAFEINSTALL_DECOY_END zzz /home/sandbox/.ssh/id_rsa",
        "SAFEINSTALL_DECOY_END MISSING /home/sandbox/.npmrc",
    ])
    assert decoy_tamper_paths(log) == ["/home/sandbox/.npmrc", "/home/sandbox/.ssh/id_rsa"]


REPORT = {"install": [
    {"requested": True, "metadata": {"name": "requests", "version": "2.32.3"},
     "download_info": {"url": "https://files.pythonhosted.org/packages/x/requests-2.32.3-py3-none-any.whl",
                       "archive_info": {"hash": "sha256=" + "a" * 64, "hashes": {"sha256": "a" * 64}}}},
    {"requested": False, "metadata": {"name": "idna", "version": "3.7"},
     "download_info": {"url": "https://files.pythonhosted.org/packages/y/idna-3.7-py3-none-any.whl",
                       "archive_info": {"hash": "sha256=" + "b" * 64}}},
]}


def test_pinned_requirements_from_pip_report():
    text, requested = pinned_requirements(REPORT)
    assert requested == "requests==2.32.3"
    assert text.splitlines() == [f"requests==2.32.3 --hash=sha256:{'a' * 64}", f"idna==3.7 --hash=sha256:{'b' * 64}"]


def test_pinned_requirements_refuses_unpinnable_installs():
    local = {"install": [{"requested": True, "metadata": {"name": "x", "version": "1"},
                          "download_info": {"url": "file:///tmp/src", "dir_info": {}}}]}
    assert pinned_requirements(local) == (None, None)
    foreign = json.loads(json.dumps(REPORT))
    foreign["install"][0]["download_info"]["url"] = "https://evil.example/requests.whl"
    assert pinned_requirements(foreign) == (None, None)


def test_pip_report_from_log():
    log = "noise\nSAFEINSTALL_PIP_REPORT_BEGIN\n{\"install\": []}\nSAFEINSTALL_PIP_REPORT_END\nmore"
    assert json.loads(pip_report_from_log(log)) == {"install": []}
    assert pip_report_from_log("nothing here") is None


def test_orchestrator_events():
    records = orchestrator_events(oom_killed=True, exit_code=124, timed_out=False,
                                  tampered_decoys=["/home/sandbox/.env"], timeout_seconds=120, now=1.0)
    kinds = [(r["type"], r["detail"].get("resource") or r["detail"].get("path")) for r in records]
    assert kinds == [("resource_limit", "memory"), ("resource_limit", "timeout"), ("file_write", "/home/sandbox/.env")]
    assert orchestrator_events(oom_killed=False, exit_code=0, timed_out=False,
                               tampered_decoys=[], timeout_seconds=120, now=1.0) == []


def test_gateway_command_runs_both_servers_with_one_log():
    assert "dns_server.py" in runplan.GATEWAY_COMMAND and "proxy.py" in runplan.GATEWAY_COMMAND
    assert runplan.GATEWAY_COMMAND.count("/gateway-log/gateway.jsonl") == 2
