"""Shared configuration for sandbox runs."""

from dataclasses import dataclass


@dataclass(frozen=True)
class SandboxLimits:
    """Hard resource limits applied to the disposable sandbox container."""

    timeout_seconds: int = 120
    memory_bytes: int = 1 * 1024 * 1024 * 1024
    nano_cpus: int = 1_000_000_000
    pids_limit: int = 256


@dataclass(frozen=True)
class SandboxHardening:
    """Docker run options that isolate and constrain the sandbox."""

    read_only_rootfs: bool = True
    tmpfs: dict[str, str] | None = None
    cap_drop: tuple[str, ...] = ("ALL",)
    security_opt: tuple[str, ...] = ("no-new-privileges:true",)

    def __post_init__(self) -> None:
        if self.tmpfs is None:
            object.__setattr__(
                self,
                "tmpfs",
                {
                    "/work": "rw,nosuid,nodev,size=1g",
                    "/tmp": "rw,exec,nosuid,nodev,size=512m",
                    "/home/sandbox": "rw,nosuid,nodev,uid=1000,gid=1000,mode=0700,size=64m",
                },
            )


def sandbox_container_kwargs(
    image: str,
    limits: SandboxLimits | None = None,
) -> dict[str, object]:
    """Return Docker SDK container options for a hardened sandbox."""
    limits = limits or SandboxLimits()
    hardening = SandboxHardening()

    assert hardening.tmpfs is not None
    return {
        "image": image,
        "read_only": hardening.read_only_rootfs,
        "tmpfs": dict(hardening.tmpfs),
        "cap_drop": list(hardening.cap_drop),
        "security_opt": list(hardening.security_opt),
        "mem_limit": limits.memory_bytes,
        "nano_cpus": limits.nano_cpus,
        "pids_limit": limits.pids_limit,
    }


def gateway_environment(proxy_url: str) -> dict[str, str]:
    """Environment variables for pip, npm, HTTP clients, and the shell."""
    if not proxy_url:
        raise ValueError("proxy_url must not be empty")
    return {
        "HTTP_PROXY": proxy_url,
        "HTTPS_PROXY": proxy_url,
        "ALL_PROXY": proxy_url,
        "http_proxy": proxy_url,
        "https_proxy": proxy_url,
        "ALL_proxy": proxy_url,
        "PIP_INDEX_URL": "https://pypi.org/simple",
        "PIP_NO_CACHE_DIR": "1",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "NPM_CONFIG_REGISTRY": "https://registry.npmjs.org/",
        "npm_config_proxy": proxy_url,
        "npm_config_https_proxy": proxy_url,
        "NO_PROXY": "127.0.0.1,localhost",
        "no_proxy": "127.0.0.1,localhost",
    }

# Single source of truth for hosts the gateway may forward. The orchestrator passes it to the
# gateway container; the rules engine imports it.
REGISTRY_ALLOWLIST = frozenset({"pypi.org", "files.pythonhosted.org", "registry.npmjs.org"})