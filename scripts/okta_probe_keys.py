"""Generate the Okta preflight probes' client keys (docs/runbooks/okta-preflight.md, step 1).

Writes fresh P-256 private keys to ``.okta-preflight/keys/`` (directory 0700, files 0600; the
directory is gitignored) and prints **only** each public JWK, to paste into the matching Okta app
(Client authentication: Public key / Private key). Existing keys are never overwritten unless
``--rotate`` is given.

    uv run python scripts/okta_probe_keys.py [--rotate] [--dir PATH]
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from trustkit.signing import InMemoryEs256Signer

CLIENTS = ("chat", "agent", "tool-gateway")
DEFAULT_DIR = pathlib.Path(__file__).parents[1] / ".okta-preflight" / "keys"


def write_key(path: pathlib.Path, *, rotate: bool) -> None:
    pem = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    flags = os.O_WRONLY | os.O_CREAT | (os.O_TRUNC if rotate else os.O_EXCL)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(pem)
    path.chmod(0o600)


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--rotate", action="store_true", help="replace existing keys")
    ap.add_argument("--dir", type=pathlib.Path, default=DEFAULT_DIR)
    args = ap.parse_args(argv)
    keys_dir: pathlib.Path = args.dir
    keys_dir.mkdir(parents=True, exist_ok=True)
    keys_dir.chmod(0o700)
    existing = [c for c in CLIENTS if (keys_dir / f"{c}.pem").exists()]
    if existing and not args.rotate:
        print(
            f"keys already exist for {', '.join(existing)}; use --rotate to replace",
            file=sys.stderr,
        )
        return 1
    for client in CLIENTS:
        path = keys_dir / f"{client}.pem"
        write_key(path, rotate=args.rotate)
        signer = InMemoryEs256Signer(path.read_bytes())
        jwk = {**signer.public_jwk(), "kid": signer.key_id, "use": "sig", "alg": "ES256"}
        print(f"# {client}: paste into the Okta app's public keys")
        print(json.dumps(jwk, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
