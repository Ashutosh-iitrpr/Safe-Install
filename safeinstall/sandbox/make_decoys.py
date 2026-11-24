#!/usr/bin/env python3
"""Generate harmless decoy credential files containing unique canary tokens."""

import argparse
import json
import secrets
from pathlib import Path


def canary(name: str) -> str:
    """Return a name-scoped random canary token."""
    return f"SAFEINSTALL_{name.upper()}_{secrets.token_hex(16)}"


def generate_decoys(home: Path, manifest: Path) -> list[dict[str, str]]:
    """Create decoy files under home and write their canary manifest."""
    home = home.resolve()
    manifest = manifest.resolve()

    decoys = [
        (
            ".env",
            "ENV",
            "SAFEINSTALL_DECOY=true\n",
        ),
        (
            ".ssh/id_rsa",
            "RSA",
            "-----BEGIN FAKE PRIVATE KEY-----\n",
        ),
        (
            ".aws/credentials",
            "AWS",
            "[safeinstall-decoy]\n",
        ),
    ]

    entries: list[dict[str, str]] = []
    for relative_path, name, prefix in decoys:
        path = home / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        token = canary(name)

        if relative_path == ".env":
            content = f"{prefix}CANARY={token}\n"
        elif relative_path == ".ssh/id_rsa":
            content = f"{prefix}{token}\n-----END FAKE PRIVATE KEY-----\n"
        else:
            content = (
                f"{prefix}"
                "aws_access_key_id=SAFEINSTALL_FAKE\n"
                f"aws_secret_access_key={token}\n"
            )

        path.write_text(content, encoding="utf-8")
        path.chmod(0o600)
        entries.append(
            {
                "path": str(path),
                "token": token,
                "kind": relative_path,
            }
        )

    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(
        json.dumps(entries, indent=2) + "\n",
        encoding="utf-8",
    )
    return entries


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, default=Path("/home/sandbox"))
    parser.add_argument(
        "--manifest",
        type=Path,
        default=Path("/work/canaries.json"),
    )
    args = parser.parse_args()
    generate_decoys(args.home, args.manifest)


if __name__ == "__main__":
    main()
