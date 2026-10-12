"""Credentials for upstream MCP servers (ADR-0018 §4)."""

from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Any, Final

from atf_mcp_gateway.servers import ServerRecord
from trustkit.binding import ActorBinding
from trustkit.exchange import ExchangeError, IdJagExchanger
from trustkit.profiles import GatewayProfile, ProfileConfigError, UnknownGatewayError, load_profiles

if TYPE_CHECKING:
    from mypy_boto3_secretsmanager import SecretsManagerClient

SECRET_CACHE_TTL_S: Final = 300


class CredentialError(Exception):
    """Log-safe: never contains secret values, ARNs or token material."""


class GatewayCredentials:
    """Implements ``proxy.Credentials``.

    ``egress_base``: an egress profile document (``egress_doc`` shape) for this gateway: its tool
    AS, its own client, ``egress_inbound`` and ``agents``. Per server, ``target`` is replaced by
    ``{"audience": record.audience, "scopes": record.scopes}`` and the result is validated by the
    strict profile schema before use.
    """

    def __init__(
        self,
        *,
        exchanger: IdJagExchanger,
        secrets: SecretsManagerClient,
        egress_base: Mapping[str, Any],
        now: Callable[[], float] = time.monotonic,
    ) -> None:
        self._exchanger, self._secrets, self._base, self._now = exchanger, secrets, egress_base, now
        self._secret_cache: dict[str, tuple[str, float]] = {}
        self._profiles: dict[tuple[str, str, tuple[str, ...]], GatewayProfile] = {}
        self._lock = threading.Lock()

    def delegated_token(self, binding: ActorBinding, record: ServerRecord) -> str:
        profile = self._profile_for(record)
        try:
            return self._exchanger.exchange_delegated(binding, profile).token
        except ExchangeError:
            raise CredentialError("delegated credential unavailable") from None

    def server_secret(self, record: ServerRecord) -> str:
        arn = record.secret_arn
        if arn is None:
            raise CredentialError("server has no credential reference")
        with self._lock:
            cached = self._secret_cache.get(arn)
            if cached is not None and self._now() - cached[1] < SECRET_CACHE_TTL_S:
                return cached[0]
        try:
            value = self._secrets.get_secret_value(SecretId=arn).get("SecretString")
        except Exception:  # noqa: BLE001 - any Secrets Manager failure; never echo the ARN
            raise CredentialError("server credential unavailable") from None
        if not isinstance(value, str) or not value:
            raise CredentialError("server credential unavailable")
        with self._lock:
            self._secret_cache[arn] = (value, self._now())
        return value

    def _profile_for(self, record: ServerRecord) -> GatewayProfile:
        if record.audience is None:
            raise CredentialError("server has no delegated audience")
        key = (record.server_id, record.audience, tuple(sorted(record.scopes)))
        with self._lock:
            if key in self._profiles:
                return self._profiles[key]
        doc = {
            **self._base,
            "target": {"audience": record.audience, "scopes": sorted(record.scopes)},
        }
        try:
            # The same strict schema as every profile: a record can't smuggle in wildcards.
            registry = load_profiles(json.dumps({"version": 1, "profiles": [doc]}))
            profile = registry.lookup(str(doc["gateway_id"]))
        except (ProfileConfigError, UnknownGatewayError, KeyError):
            raise CredentialError("server delegation profile invalid") from None
        with self._lock:
            self._profiles[key] = profile
        return profile
