"""Generate everything the local stack needs into one gitignored directory (ADR-0015 §3).

Output layout (``out_dir``, created with mode 0700)::

    ca.pem                       CA certificate (trusted by every container)
    ca.key                       CA private key; only needed to re-issue, never mounted
    <service>.pem / .key         leaf cert + key for each service hostname
    client-keys/<name>.pem       private_key_jwt keys for local:<name> signer refs
    mock-idp-topology.json       authorization servers, clients (public JWKS), exchange policy
    profiles.json                interceptor gateway profiles (version 1)

Rules:
* All keys are ECDSA P-256. Private key files are mode 0600.
* CA: ``CA:TRUE, pathlen:0``, keyUsage ``keyCertSign, cRLSign``, valid ``validity_days``
  (default 7).
* Leaves: ``CA:FALSE``, keyUsage ``digitalSignature``, EKU ``serverAuth``, SAN = exactly the
  service's DNS names, signed by the CA, same validity cap.
* Every run creates a brand-new CA. Nothing is reused across runs (ephemeral by design).
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from joserfc.jwk import thumbprint

from trustkit.signing import es256_public_jwk

DEFAULT_VALIDITY_DAYS: Final = 7
MAX_VALIDITY_DAYS: Final = 30


@dataclass(frozen=True)
class Service:
    name: str
    """File stem and primary DNS name."""
    dns_names: tuple[str, ...]


FRONTEND_CLIENT_ID: Final = "0oa-chat"
FRONTEND_KEY_NAME: Final = "chat"
AGENT: Final = "agent-alpha"
AGENT_AUDIENCE: Final = "api://agent-alpha"
INGRESS_AS: Final = "ingress"
INGRESS_AUDIENCE: Final = "api://agent-ingress"
GATEWAY_ID: Final = "gw-alpha"
AGENT_CLIENT_ID: Final = "0oa-agent-alpha"
TOOL_GATEWAY_CLIENT_ID: Final = "0oa-tool-gateway"
ADMIN_CLIENT_IDS: Final = ("0oa-admin-alice", "0oa-admin-bob")
TOOL_AS: Final = "tool-tickets"
TOOL_AUDIENCE: Final = "api://tool-tickets"
WORKLOAD_AS: Final = "workload"
WORKLOAD_AUDIENCE: Final = "api://tool-gateway"
ADMIN_AS: Final = "admin"
ADMIN_AUDIENCE: Final = "api://mcp-admin"
MOCK_MCP_HOST: Final = "mock-mcp.tools.internal"
INFERENCE_AS: Final = "inference"
INFERENCE_AUDIENCE: Final = "api://inference-gateway"
LOGICAL_MODEL: Final = "claude-sonnet"
REGISTRY_AS: Final = "registry"
REGISTRY_AUDIENCE: Final = "api://agent-registry"
REGISTRY_ADMINS: Final = {
    # client id -> groups (ADR-0021 §2): author, approver, security approver.
    "0oa-reg-dave": ("team-alpha",),
    "0oa-reg-bob": ("atf-registry-approvers",),
    "0oa-reg-carol": ("atf-security-approvers",),
}
ENTITLED_USERS: Final = ("00u-alice",)
"""Users entitled to delegate ``tickets.read`` (ADR-0023 §1); everyone else is downscoped."""
BUNDLE_ISSUER: Final = "atf-bundle-publisher"
AGENT_BETA: Final = "agent-beta"
AGENT_BETA_AUDIENCE: Final = "api://agent-beta"
AGENT_BETA_CLIENT_ID: Final = "0oa-agent-beta"
A2A_CLIENT_ID: Final = "0oa-a2a-gateway"

# key file name -> client id
CLIENT_KEYS: Final = {
    "chat": "0oa-chat",
    "agent": AGENT_CLIENT_ID,
    "gateway": TOOL_GATEWAY_CLIENT_ID,
    "admin-alice": ADMIN_CLIENT_IDS[0],
    "admin-bob": ADMIN_CLIENT_IDS[1],
    "reg-dave": "0oa-reg-dave",
    "reg-bob": "0oa-reg-bob",
    "reg-carol": "0oa-reg-carol",
    "agent-beta": "0oa-agent-beta",
    "a2a-gateway": "0oa-a2a-gateway",
}

DEFAULT_SERVICES: Final = (
    Service("mock-idp", ("mock-idp", "localhost")),
    Service("gateway", ("gateway", "localhost")),
    Service("agent-runtime", ("agent-runtime",)),
    Service("mcp-gateway", ("mcp-gateway", "localhost")),
    Service("mcp-admin", ("mcp-admin", "localhost")),
    Service("mock-mcp", (MOCK_MCP_HOST,)),
    Service("inference-gateway", ("inference-gateway", "localhost")),
    Service("mock-llm", ("mock-llm",)),
    Service("agent-registry", ("agent-registry", "localhost")),
    Service("a2a-gateway", ("a2a-gateway", "localhost")),
    # FQDN for the A2A gateway (SSRF vetting requires one); bare name for its own healthcheck.
    Service("agent-beta", ("agent-beta.agents.internal", "agent-beta")),
)


@dataclass(frozen=True)
class BootstrapResult:
    out_dir: pathlib.Path
    ca_cert: pathlib.Path
    service_certs: Mapping[str, tuple[pathlib.Path, pathlib.Path]]
    client_keys: Mapping[str, pathlib.Path]
    topology: pathlib.Path
    profiles: pathlib.Path


def bootstrap(
    out_dir: pathlib.Path,
    *,
    idp_base_url: str = "https://mock-idp:8443",
    services: Sequence[Service] = DEFAULT_SERVICES,
    validity_days: int = DEFAULT_VALIDITY_DAYS,
) -> BootstrapResult:
    if not 1 <= validity_days <= MAX_VALIDITY_DAYS:
        raise ValueError(f"validity must be within 1..{MAX_VALIDITY_DAYS} days")
    out_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    out_dir.chmod(0o700)
    now = dt.datetime.now(dt.UTC)
    not_before, not_after = now - dt.timedelta(minutes=5), now + dt.timedelta(days=validity_days)

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "agent-trust-fabric local CA")])
    ca_ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_key_usage(cert_sign=True), critical=True)
        .add_extension(ca_ski, critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    ca_cert_path = out_dir / "ca.pem"
    _write(ca_cert_path, ca_cert.public_bytes(serialization.Encoding.PEM), 0o644)
    _write(out_dir / "ca.key", _pem(ca_key), 0o600)

    service_certs: dict[str, tuple[pathlib.Path, pathlib.Path]] = {}
    for svc in services:
        key = ec.generate_private_key(ec.SECP256R1())
        leaf = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, svc.name)]))
            .issuer_name(ca_name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(not_before)
            .not_valid_after(not_after)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(_key_usage(cert_sign=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName(n) for n in svc.dns_names]),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        crt, k = out_dir / f"{svc.name}.pem", out_dir / f"{svc.name}.key"
        _write(crt, leaf.public_bytes(serialization.Encoding.PEM), 0o644)
        _write(k, _pem(key), 0o600)
        service_certs[svc.name] = (crt, k)

    keys_dir = out_dir / "client-keys"
    keys_dir.mkdir(mode=0o700, exist_ok=True)
    keys_dir.chmod(0o700)
    client_key_paths: dict[str, pathlib.Path] = {}
    public_jwks: dict[str, dict[str, str]] = {}
    for name, client_id in CLIENT_KEYS.items():
        key = ec.generate_private_key(ec.SECP256R1())
        path = keys_dir / f"{name}.pem"
        _write(path, _pem(key), 0o600)
        jwk = es256_public_jwk(key.public_key())
        jwk["kid"] = thumbprint(jwk)
        client_key_paths[name], public_jwks[client_id] = path, jwk

    base = idp_base_url.rstrip("/")
    topology_path, profiles_path = out_dir / "mock-idp-topology.json", out_dir / "profiles.json"
    _write(topology_path, _json(_topology(base, public_jwks)), 0o644)
    _write(profiles_path, _json(_profiles(base)), 0o644)
    _write(out_dir / "mcp-egress.json", _json(_mcp_egress(base)), 0o644)
    _write(out_dir / "inference-profile.json", _json(_inference_profile(base)), 0o644)
    _write(out_dir / "model-routes.json", _json(_model_routes()), 0o644)
    _write(out_dir / "a2a-egress.json", _json(_a2a_egress(base)), 0o644)

    # Bundle signing key (ADR-0022 §7): only the publisher mounts this directory; gateways get
    # the public JWK. Never under client-keys/ (which other containers mount files from).
    signing_dir = out_dir / "bundle-signing"
    signing_dir.mkdir(mode=0o700, exist_ok=True)
    signing_dir.chmod(0o700)
    bundle_key = ec.generate_private_key(ec.SECP256R1())
    _write(signing_dir / "bundle.pem", _pem(bundle_key), 0o600)
    bundle_jwk = es256_public_jwk(bundle_key.public_key())
    _write(out_dir / "bundle-key.jwk", _json(bundle_jwk), 0o644)
    bundles_dir = out_dir / "bundles"  # publisher writes, gateways mount read-only
    bundles_dir.mkdir(mode=0o755, exist_ok=True)
    bundles_dir.chmod(0o755)

    return BootstrapResult(
        out_dir=out_dir,
        ca_cert=ca_cert_path,
        service_certs=service_certs,
        client_keys=client_key_paths,
        topology=topology_path,
        profiles=profiles_path,
    )


def _key_usage(*, cert_sign: bool) -> x509.KeyUsage:
    return x509.KeyUsage(
        digital_signature=not cert_sign,
        content_commitment=False,
        key_encipherment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=cert_sign,
        crl_sign=cert_sign,
        encipher_only=False,
        decipher_only=False,
    )


def _pem(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def _json(obj: Any) -> bytes:
    return (json.dumps(obj, indent=2, sort_keys=True) + "\n").encode()


def _write(path: pathlib.Path, data: bytes, mode: int) -> None:
    """Create with the final mode from the start (no window where a key is world-readable)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        os.write(fd, data)
    finally:
        os.close(fd)
    path.chmod(mode)  # O_CREAT ignores mode for pre-existing files


def _topology(base: str, jwks: Mapping[str, Mapping[str, str]]) -> dict[str, Any]:
    def client(cid: str, policy: Mapping[str, list[str]]) -> dict[str, Any]:
        return {
            "client_id": cid,
            "jwks": {"keys": [dict(jwks[cid])]},
            "exchange_policy": dict(policy),
        }

    return {
        "authorization_servers": [
            {
                "as_id": INGRESS_AS,
                "resource_audience": INGRESS_AUDIENCE,
                "clients": [FRONTEND_CLIENT_ID],
            },
            {
                "as_id": AGENT,
                "resource_audience": AGENT_AUDIENCE,
                "clients": [FRONTEND_CLIENT_ID],
                "agent_client_id": AGENT_CLIENT_ID,
                "restricted_scopes": {"tickets.read": list(ENTITLED_USERS)},
            },
            {
                # Agent B's own AS: only the A2A gateway may exchange here (ADR-0024 §1).
                "as_id": AGENT_BETA,
                "resource_audience": AGENT_BETA_AUDIENCE,
                "clients": [A2A_CLIENT_ID],
                "agent_client_id": AGENT_BETA_CLIENT_ID,
                "restricted_scopes": {"tickets.read": list(ENTITLED_USERS)},
            },
            {
                "as_id": REGISTRY_AS,
                "resource_audience": REGISTRY_AUDIENCE,
                "clients": list(REGISTRY_ADMINS),
            },
            {
                "as_id": WORKLOAD_AS,
                "resource_audience": WORKLOAD_AUDIENCE,
                "clients": [AGENT_CLIENT_ID, AGENT_BETA_CLIENT_ID],
            },
            {
                "as_id": INFERENCE_AS,
                "resource_audience": INFERENCE_AUDIENCE,
                "clients": [AGENT_CLIENT_ID],
            },
            {
                "as_id": TOOL_AS,
                "resource_audience": TOOL_AUDIENCE,
                "clients": [TOOL_GATEWAY_CLIENT_ID],
            },
            {
                "as_id": ADMIN_AS,
                "resource_audience": ADMIN_AUDIENCE,
                "clients": list(ADMIN_CLIENT_IDS),
            },
        ],
        "clients": [
            client(
                FRONTEND_CLIENT_ID, {f"{base}/oauth2/{AGENT}": ["agent.invoke", "tickets.read"]}
            ),
            client(
                AGENT_CLIENT_ID,
                {
                    f"{base}/oauth2/{WORKLOAD_AS}": ["tools.invoke"],
                    f"{base}/oauth2/{INFERENCE_AS}": ["inference.invoke"],
                },
            ),
            client(TOOL_GATEWAY_CLIENT_ID, {f"{base}/oauth2/{TOOL_AS}": ["tickets.read"]}),
            client(AGENT_BETA_CLIENT_ID, {f"{base}/oauth2/{WORKLOAD_AS}": ["tools.invoke"]}),
            client(
                A2A_CLIENT_ID,
                {f"{base}/oauth2/{AGENT_BETA}": ["agent.invoke", "tickets.read"]},
            ),
            *(
                client(cid, {f"{base}/oauth2/{ADMIN_AS}": ["mcp.admin"]})
                for cid in ADMIN_CLIENT_IDS
            ),
            *(
                {
                    **client(cid, {f"{base}/oauth2/{REGISTRY_AS}": ["registry.admin"]}),
                    "groups": list(groups),
                }
                for cid, groups in REGISTRY_ADMINS.items()
            ),
        ],
    }


def _mcp_egress(base: str) -> dict[str, Any]:
    """Egress profile base for the MCP gateway (ADR-0016/0018). ``target`` and ``server_id`` are
    set per server record; which agents may use a server comes from the policy bundle."""
    return {
        "profile_id": "mcp-gateway",
        "gateway_id": "mcp-gateway",
        "flow": "egress",
        "enabled": True,
        "idp": {
            "issuer": base,
            "jwks_uri": f"{base}/oauth2/v1/keys",
            "token_endpoint": f"{base}/oauth2/v1/token",
            "resource_issuer": f"{base}/oauth2/{TOOL_AS}",
            "resource_token_endpoint": f"{base}/oauth2/{TOOL_AS}/v1/token",
            "resource_jwks_uri": f"{base}/oauth2/{TOOL_AS}/v1/keys",
        },
        "target": {"audience": TOOL_AUDIENCE, "scopes": ["tickets.read"]},
        "client": {"client_id": TOOL_GATEWAY_CLIENT_ID, "signing_key": "local:gateway"},
        "egress_inbound": {
            "issuer": f"{base}/oauth2/{WORKLOAD_AS}",
            "audiences": [WORKLOAD_AUDIENCE],
            "jwks_uri": f"{base}/oauth2/{WORKLOAD_AS}/v1/keys",
        },
    }


def _inference_profile(base: str) -> dict[str, Any]:
    """Inference gateway profile (ADR-0019): its own audience, so tool-gateway tokens don't work.
    Model grants and budgets come from the policy bundle (ADR-0022)."""
    return {
        "inbound": {
            "issuer": f"{base}/oauth2/{INFERENCE_AS}",
            "audiences": [INFERENCE_AUDIENCE],
            "jwks_uri": f"{base}/oauth2/{INFERENCE_AS}/v1/keys",
        },
        "scanner_failure_mode": "closed",
    }


def _model_routes() -> dict[str, Any]:
    """Local only: the logical model goes to mock-llm on the internal `llm` network (ADR-0020)."""
    return {
        LOGICAL_MODEL: {
            "provider_model": "openai/mock-sonnet",
            "api_base": "https://mock-llm:8443/v1",
        }
    }


def _a2a_egress(base: str) -> dict[str, Any]:
    """A2A gateway egress base (ADR-0024 §1). ``idp.resource_*``, ``target`` and ``server_id``
    are replaced per target agent from its signed grant; the values here only satisfy the
    schema (they name agent-beta's AS)."""
    return {
        "profile_id": "a2a-gateway",
        "gateway_id": "a2a-gateway",
        "flow": "egress",
        "enabled": True,
        "idp": {
            "issuer": base,
            "jwks_uri": f"{base}/oauth2/v1/keys",
            "token_endpoint": f"{base}/oauth2/v1/token",
            "resource_issuer": f"{base}/oauth2/{AGENT_BETA}",
            "resource_token_endpoint": f"{base}/oauth2/{AGENT_BETA}/v1/token",
            "resource_jwks_uri": f"{base}/oauth2/{AGENT_BETA}/v1/keys",
        },
        "client": {"client_id": A2A_CLIENT_ID, "signing_key": "local:a2a-gateway"},
        "egress_inbound": {
            "issuer": f"{base}/oauth2/{WORKLOAD_AS}",
            "audiences": [WORKLOAD_AUDIENCE],
            "jwks_uri": f"{base}/oauth2/{WORKLOAD_AS}/v1/keys",
        },
    }


def _profiles(base: str) -> dict[str, Any]:
    return {
        "version": 1,
        "profiles": [
            {
                "profile_id": f"{AGENT}-ingress",
                "gateway_id": GATEWAY_ID,
                "flow": "ingress",
                "enabled": True,
                "idp": {
                    "issuer": base,
                    "jwks_uri": f"{base}/oauth2/v1/keys",
                    "token_endpoint": f"{base}/oauth2/v1/token",
                    "resource_issuer": f"{base}/oauth2/{AGENT}",
                    "resource_token_endpoint": f"{base}/oauth2/{AGENT}/v1/token",
                    "resource_jwks_uri": f"{base}/oauth2/{AGENT}/v1/keys",
                },
                # Downstream scopes the agent may use for the user; the IdP downscopes per user.
                "target": {"audience": AGENT_AUDIENCE, "scopes": ["agent.invoke", "tickets.read"]},
                "ingress_clients": {FRONTEND_CLIENT_ID: f"local:{FRONTEND_KEY_NAME}"},
                "max_auth_age_s": 43_200,
                "ingress_token": {
                    "issuer": f"{base}/oauth2/{INGRESS_AS}",
                    "audiences": [INGRESS_AUDIENCE],
                    "jwks_uri": f"{base}/oauth2/{INGRESS_AS}/v1/keys",
                },
            }
        ],
    }


def main(argv: Sequence[str] | None = None) -> int:
    """``python -m devstack.bootstrap --out .local-ca``"""
    parser = argparse.ArgumentParser(description="Generate the ephemeral local stack material.")
    parser.add_argument("--out", type=pathlib.Path, default=pathlib.Path(".local-ca"))
    parser.add_argument("--idp-base-url", default="https://mock-idp:8443")
    parser.add_argument("--validity-days", type=int, default=DEFAULT_VALIDITY_DAYS)
    args = parser.parse_args(argv)
    result = bootstrap(args.out, idp_base_url=args.idp_base_url, validity_days=args.validity_days)
    print(f"local CA and configs written to {result.out_dir} (private keys mode 0600)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
