"""Signer factory shared by every service that signs client assertions (ADR-0007/0015).

``arn:aws:kms:...`` -> ``KmsEs256Signer``; ``local:<name>`` -> ``InMemoryEs256Signer`` from
``ATF_LOCAL_KEYS_DIR``, **only** when ``ATF_ENV=local``. Anything else raises ``SigningError``.
"""

from __future__ import annotations

import pathlib
import re
import threading
from collections.abc import Callable, Mapping
from typing import Final

from trustkit.signing import InMemoryEs256Signer, KeySigner, SigningError

SignerFactory = Callable[[str], KeySigner]

_LOCAL_NAME: Final = re.compile(r"^[a-z0-9-]{1,64}$")
_KMS_ARN: Final = re.compile(r"^arn:aws:kms:([a-z0-9-]+):\d{12}:key/[0-9a-f-]{36}$")


def make_signer_factory(env: Mapping[str, str]) -> SignerFactory:
    """``arn:aws:kms:...`` -> KMS signer. ``local:<name>`` -> in-memory signer (local only).

    Signers are memoised per reference. Unknown or disallowed references raise ``SigningError``.
    """
    cache: dict[str, KeySigner] = {}
    lock = threading.Lock()
    local_allowed = env.get("ATF_ENV") == "local"
    keys_dir = env.get("ATF_LOCAL_KEYS_DIR")

    def build(ref: str) -> KeySigner:
        if (m := _KMS_ARN.fullmatch(ref)) is not None:
            import boto3  # lazy: keeps cold start lean when only local keys are used

            from trustkit_aws.kms import KmsEs256Signer

            return KmsEs256Signer(boto3.client("kms", region_name=m.group(1)), ref)
        if ref.startswith("local:"):
            if not local_allowed:
                raise SigningError("local signing keys are disabled outside ATF_ENV=local")
            name = ref.removeprefix("local:")
            if not _LOCAL_NAME.fullmatch(name) or not keys_dir:
                raise SigningError("invalid local key reference")
            try:
                pem = (pathlib.Path(keys_dir) / f"{name}.pem").read_bytes()
            except (OSError, ValueError):
                raise SigningError("local signing key unavailable") from None
            signer = InMemoryEs256Signer(pem)
            _ = signer.key_id  # load + validate now: fail at first use, not mid-request
            return signer
        raise SigningError("unsupported key reference")

    def factory(ref: str) -> KeySigner:
        with lock:
            if ref not in cache:
                cache[ref] = build(ref)
            return cache[ref]

    return factory
