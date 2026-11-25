#!/usr/bin/env python3
"""Generate realistic-looking decoy credential files seeded with canary tokens.

Tokens normally come from the host via SAFEINSTALL_CANARIES (JSON: {kind: token}),
so the analyzer never has to trust a file the sandbox can edit.
"""

import argparse
import json
import os
import secrets
import string
from pathlib import Path

_ALNUM = string.ascii_letters + string.digits

TEMPLATES = {
    ".env": (
        "NODE_ENV=production\n"
        "DATABASE_URL=postgresql://app:Tr0ub4dor3x@db.internal:5432/app\n"
        "STRIPE_SECRET_KEY={token}\n"
    ),
    ".ssh/id_rsa": (
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABFwAAAAdzc2gtcn\n"
        "{token}\n"
        "-----END OPENSSH PRIVATE KEY-----\n"
    ),
    ".aws/credentials": (
        "[default]\n"
        "aws_access_key_id = {aws_key_id}\n"
        "aws_secret_access_key = {token}\n"
        "region = us-east-1\n"
    ),
    ".npmrc": "//npm.pkg.github.com/:_authToken={token}\n",
    ".pypirc": (
        "[distutils]\nindex-servers =\n    pypi\n\n"
        "[pypi]\nusername = __token__\npassword = {token}\n"
    ),
    ".git-credentials": "https://deploy-bot:{token}@github.com\n",
}


def _rand(length: int) -> str:
    return "".join(secrets.choice(_ALNUM) for _ in range(length))


def generate_decoys(
    home: Path,
    manifest: Path,
    tokens: dict[str, str] | None = None,
) -> list[dict[str, str]]:
    """Create decoy files under home and write their canary manifest."""
    home = home.resolve()
    manifest = manifest.resolve()
    tokens = tokens or {}
    aws_key_id = os.environ.get("AWS_ACCESS_KEY_ID") or "AKIA" + _rand(16).upper()

    entries: list[dict[str, str]] = []
    for kind, template in TEMPLATES.items():
        token = tokens.get(kind) or _rand(40)
        path = home / kind
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(template.format(token=token, aws_key_id=aws_key_id), encoding="utf-8")
        path.chmod(0o600)
        entries.append({"path": str(path), "token": token, "kind": kind})

    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text(json.dumps(entries, indent=2) + "\n", encoding="utf-8")
    return entries


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--home", type=Path, default=Path("/home/sandbox"))
    parser.add_argument("--manifest", type=Path, default=Path("/work/canaries.json"))
    args = parser.parse_args()
    raw = os.environ.get("SAFEINSTALL_CANARIES")
    generate_decoys(args.home, args.manifest, json.loads(raw) if raw else None)


if __name__ == "__main__":
    main()
