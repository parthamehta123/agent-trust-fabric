"""Gateway profiles: strict schema and fail-closed loading.

Config document shape::

    {"version": 1, "profiles": [ {<GatewayProfile>}, ... ]}

Loading rules (TM-EXC-05, architecture §8):

* Document missing, not JSON, wrong ``version``, or ``profiles`` not a list
  -> ``ProfileConfigError`` (the caller must deny everything).
* An individual profile fails validation -> it is dropped and listed in ``rejected``.
  Other profiles still load.
* Two profiles claim the same ``gateway_id`` -> **both** are dropped (ambiguity is a deny).
* Lookup of an unknown ``gateway_id`` -> ``UnknownGatewayError``.

Rejection reasons never echo field *values*, since a misconfigured profile might hold a
secret in the wrong field.
"""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Annotated, Any, Final, NoReturn, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    ValidationError,
    model_validator,
)

PLATFORM_MAX_SCANNER_TIMEOUT_MS: Final = 2_000
SUPPORTED_CONFIG_VERSION: Final = 1
MAX_CONFIG_BYTES: Final = 1_048_576
_MAX_LOC_PART: Final = 64

Slug = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9-]{1,62}$")]
HttpsUrl = Annotated[str, StringConstraints(pattern=r"^https://[^\s/$.?#][^\s]*$", max_length=2048)]
Scope = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9:._/-]{1,128}$")]
"""No ``*``: wildcard scopes are rejected by construction (TM-EXC-02)."""
KeyRef = Annotated[
    str,
    StringConstraints(
        pattern=r"^(arn:aws:kms:[a-z0-9-]+:\d{12}:key/[0-9a-f-]{36}|local:[a-z0-9-]{1,64})$"
    ),
]
"""A KMS key ARN, or ``local:<name>`` for the in-memory signer used in tests (ADR-0007)."""


class _Strict(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class Flow(StrEnum):
    INGRESS = "ingress"
    EGRESS = "egress"


class ScannerFailureMode(StrEnum):
    CLOSED = "closed"
    OPEN = "open"


class IdpSettings(_Strict):
    issuer: HttpsUrl
    jwks_uri: HttpsUrl
    token_endpoint: HttpsUrl
    """Where the ID-JAG is requested (RFC 8693 token exchange)."""
    resource_issuer: HttpsUrl
    """Issuer of the target's resource AS. Becomes the ID-JAG ``audience``."""
    resource_token_endpoint: HttpsUrl
    """Where the ID-JAG is redeemed for T2 (RFC 7523 JWT-bearer)."""
    resource_jwks_uri: HttpsUrl
    """Keys of the resource AS, for post-mint T2 validation (ADR-0011)."""


ClientId = Annotated[str, StringConstraints(min_length=1, max_length=256)]


class ClientAuth(_Strict):
    client_id: ClientId
    signing_key: KeyRef


class IngressToken(_Strict):
    """How the interceptor re-validates the caller's access token (defence in depth on top of
    the gateway's own JWT authorizer)."""

    issuer: HttpsUrl
    audiences: Annotated[
        frozenset[Annotated[str, StringConstraints(min_length=1)]], Field(min_length=1)
    ]
    jwks_uri: HttpsUrl


class Target(_Strict):
    audience: Annotated[str, StringConstraints(min_length=1, max_length=512)]
    scopes: Annotated[frozenset[Scope], Field(min_length=1)]


class GatewayProfile(_Strict):
    profile_id: Slug
    gateway_id: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    flow: Flow
    enabled: bool
    """Kill switch / staged rollout. ``False`` means the interceptor denies every request for
    this gateway. It never means "forward the caller's token unchanged"."""
    idp: IdpSettings
    target: Target
    scanner_failure_mode: ScannerFailureMode = ScannerFailureMode.CLOSED
    scanner_timeout_ms: Annotated[int, Field(gt=0, le=PLATFORM_MAX_SCANNER_TIMEOUT_MS)] = 800
    response_body_scan: bool = True
    """``False`` only for egress profiles, where scanning moves into the inference gateway
    (ADR-0012 §6). Ingress responses are always scanned."""

    # Egress only: the agent's own client (ADR-0007). Required for egress, forbidden for ingress.
    client: ClientAuth | None = None

    # Ingress only (ADR-0006, ADR-0009). Required for ingress, forbidden for egress.
    ingress_clients: Annotated[dict[ClientId, KeyRef], Field(min_length=1)] | None = None
    """Front-end clients allowed to drive exchanges for this agent, each with its signing key."""
    max_auth_age_s: Annotated[int, Field(gt=0, le=86_400)] | None = None
    """Upper bound on ``now - IDT.auth_time``: how old the user's actual login may be."""
    ingress_token: IngressToken | None = None

    @model_validator(mode="after")
    def _flow_specific_fields(self) -> Self:
        ingress_fields = (self.ingress_clients, self.max_auth_age_s, self.ingress_token)
        if self.flow is Flow.INGRESS:
            if any(f is None for f in ingress_fields) or self.client is not None:
                raise ValueError("ingress: needs ingress_clients/max_auth_age_s/ingress_token")
            if not self.response_body_scan:
                raise ValueError("ingress: response_body_scan cannot be disabled")
        elif any(f is not None for f in ingress_fields) or self.client is None:
            raise ValueError("egress: needs client, no ingress-only fields")
        return self


class ProfileConfigError(Exception):
    """Top-level config unusable. The interceptor must deny all requests."""


class UnknownGatewayError(LookupError):
    """No valid profile for this gateway. The interceptor must deny."""


@dataclass(frozen=True)
class ProfileRegistry:
    by_gateway_id: Mapping[str, GatewayProfile]
    rejected: Mapping[str, str]
    """``"profiles[<index>]"`` or ``"gateway_id=<id>"`` -> reason. Never contains field values."""

    def lookup(self, gateway_id: str) -> GatewayProfile:
        profile = self.by_gateway_id.get(gateway_id)
        if profile is None:
            raise UnknownGatewayError("no valid profile for gateway")
        return profile


class _TopLevel(_Strict):
    version: int
    profiles: list[Any]


def _reject_constant(name: str) -> NoReturn:
    raise ValueError(f"non-standard JSON constant {name}")


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        raise ValueError("duplicate object key")
    return dict(pairs)


def _safe_reason(err: ValidationError) -> str:
    """Field locations and error *types* only: pydantic's ``input``/``msg`` can echo values."""
    parts = []
    for e in err.errors(include_url=False, include_input=False, include_context=False):
        loc = ".".join(str(x)[:_MAX_LOC_PART] for x in e["loc"]) or "<profile>"
        parts.append(f"{loc}: {e['type']}")
    return "; ".join(sorted(parts))


def load_profiles(raw: str | bytes | None) -> ProfileRegistry:
    if raw is None:
        raise ProfileConfigError("profile config missing")
    if len(raw) > MAX_CONFIG_BYTES:
        raise ProfileConfigError("profile config too large")
    try:
        text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
        doc = json.loads(
            text, parse_constant=_reject_constant, object_pairs_hook=_no_duplicate_keys
        )
        top = _TopLevel.model_validate(doc)
    except (UnicodeDecodeError, ValueError, RecursionError):
        # ValidationError is a ValueError. The cause is dropped on purpose: parser and pydantic
        # messages can echo config values, and this exception is logged.
        raise ProfileConfigError("profile config unparseable") from None
    if top.version != SUPPORTED_CONFIG_VERSION:
        raise ProfileConfigError("unsupported profile config version")

    rejected: dict[str, str] = {}
    valid: list[GatewayProfile] = []
    for i, item in enumerate(top.profiles):
        try:
            # JSON mode gives strict *JSON* semantics: arrays -> frozenset, enums by value.
            valid.append(GatewayProfile.model_validate_json(json.dumps(item)))
        except ValidationError as e:
            rejected[f"profiles[{i}]"] = _safe_reason(e)

    dup_gateways = {k for k, n in Counter(p.gateway_id for p in valid).items() if n > 1}
    dup_profiles = {k for k, n in Counter(p.profile_id for p in valid).items() if n > 1}
    for gid in sorted(dup_gateways):
        rejected[f"gateway_id={gid}"] = "duplicate gateway_id"
    for pid in sorted(dup_profiles):
        rejected[f"profile_id={pid}"] = "duplicate profile_id"

    by_gateway = {
        p.gateway_id: p
        for p in valid
        if p.gateway_id not in dup_gateways and p.profile_id not in dup_profiles
    }
    return ProfileRegistry(
        by_gateway_id=MappingProxyType(by_gateway), rejected=MappingProxyType(rejected)
    )
