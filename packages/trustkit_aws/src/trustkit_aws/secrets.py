"""Secrets Manager reads for small binary keys (ADR-0028: the per-plane DPoP nonce key)."""

from __future__ import annotations

import base64
import binascii
from collections.abc import Callable

from botocore.exceptions import BotoCoreError, ClientError


class SecretUnavailableError(Exception):
    """Log-safe: never contains secret material, the ARN's value or AWS error text."""


def secret_bytes_fetcher(region: str, client: object | None = None) -> Callable[[str], bytes]:
    """``arn -> bytes``. The secret is a base64 ``SecretString`` (what Terraform writes) or a
    ``SecretBinary``. Any failure raises ``SecretUnavailableError`` (a cold-start failure)."""

    def fetch(arn: str) -> bytes:
        import boto3

        sm = client or boto3.client("secretsmanager", region_name=region)
        try:
            r = sm.get_secret_value(SecretId=arn)  # type: ignore[attr-defined]
        except (ClientError, BotoCoreError):
            raise SecretUnavailableError("secret unavailable") from None
        if "SecretBinary" in r:
            return bytes(r["SecretBinary"])
        try:
            return base64.b64decode(r["SecretString"], validate=True)
        except (KeyError, ValueError, binascii.Error):
            raise SecretUnavailableError("secret is not base64") from None

    return fetch
