"""3b-ii-a: local SSRF allowlist, DynamoDB store, credentials adapter, HTTP shells (ADR-0018)."""

from __future__ import annotations

import ipaddress
import json
from collections.abc import Iterator, Mapping
from typing import Any

import boto3
import pytest
from atf_mcp_gateway.admin import AdminService
from atf_mcp_gateway.app import create_admin_app, create_data_app
from atf_mcp_gateway.credentials import CredentialError, GatewayCredentials
from atf_mcp_gateway.proxy import McpProxy
from atf_mcp_gateway.servers import (
    Delegation,
    InMemoryServerStore,
    ServerRecord,
    ServerStatus,
    SnapshotTooLargeError,
    StoreConflictError,
)
from atf_mcp_gateway.snapshot import take_snapshot
from atf_mcp_gateway.ssrf import SsrfConfigError, SsrfError, parse_local_allowlist, vet_url
from atf_mcp_gateway.store_dynamo import DynamoServerStore
from fastapi.testclient import TestClient
from joserfc.jwk import RSAKey
from moto import mock_aws

from tests.conftest import AUDIENCE, ISSUER, NOW, Mint, StaticKeys, good_claims
from tests.exchange.conftest import TOOL_AUDIENCE, World, egress_doc
from tests.mcp_gateway.test_proxy import BINDING, Upstream, call, record
from tests.mcp_gateway.test_snapshot import TOOLS
from trustkit.binding import ActorBindingError, ActorBindingReason
from trustkit.jwt import TokenValidator, ValidationPolicy
from trustkit.scanning import LocalRulesScanner

SECRET_ARN_NAME = "weather-key"


# ----------------------------------------------------------------------------- SSRF allowlist


@pytest.mark.security
class TestLocalAllowlist:
    def test_unset_is_empty(self) -> None:
        assert parse_local_allowlist({"ATF_ENV": "prod"}) == frozenset()

    def test_local_subnet(self) -> None:
        nets = parse_local_allowlist({"ATF_ENV": "local", "ATF_SSRF_ALLOW_CIDRS": "172.30.0.0/16"})
        assert nets == frozenset({ipaddress.ip_network("172.30.0.0/16")})

    @pytest.mark.parametrize("env_name", ["prod", "staging", "", "LOCAL"])
    def test_refused_outside_local(self, env_name: str) -> None:
        """ADR-0018 §1: an SSRF exception must never be configurable in a real environment."""
        with pytest.raises(SsrfConfigError):
            parse_local_allowlist({"ATF_ENV": env_name, "ATF_SSRF_ALLOW_CIDRS": "172.30.0.0/16"})

    @pytest.mark.parametrize(
        "cidr",
        [
            "0.0.0.0/0",
            "10.0.0.0/8",
            "169.254.0.0/16",
            "169.254.169.254/32",
            "8.8.8.0/24",
            "fe80::/64",
            "::/0",
            "fd00::/8",
            "not-a-cidr",
            "172.30.0.1/16",
        ],
    )
    def test_unsafe_cidrs_refused(self, cidr: str) -> None:
        with pytest.raises(SsrfConfigError):
            parse_local_allowlist({"ATF_ENV": "local", "ATF_SSRF_ALLOW_CIDRS": cidr})

    def test_allow_opens_only_that_subnet(self) -> None:
        allow = parse_local_allowlist({"ATF_ENV": "local", "ATF_SSRF_ALLOW_CIDRS": "172.30.0.0/16"})
        vet_url(
            "https://mock-mcp.tools.internal/mcp", resolver=lambda h, p: ["172.30.0.7"], allow=allow
        )
        for ip in ("172.31.0.7", "169.254.169.254", "127.0.0.1"):
            with pytest.raises(SsrfError):
                vet_url(
                    "https://mock-mcp.tools.internal/mcp",
                    resolver=lambda h, p, ip=ip: [ip],
                    allow=allow,
                )


# ----------------------------------------------------------------------------- DynamoDB store


@pytest.fixture
def ddb() -> Iterator[DynamoServerStore]:
    with mock_aws():
        client = boto3.client("dynamodb", region_name="us-east-1")
        client.create_table(
            TableName="mcp-servers",
            KeySchema=[{"AttributeName": "server_id", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "server_id", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        yield DynamoServerStore(client, "mcp-servers")


class TestDynamoStore:
    def test_roundtrip(self, ddb: DynamoServerStore) -> None:
        rec = record("tickets", TOOLS)
        ddb.put(rec, expected_status=None)
        got = ddb.get("tickets")
        assert got == rec
        assert got is not None
        assert got.callable
        assert [r.server_id for r in ddb.list()] == ["tickets"]

    def test_missing(self, ddb: DynamoServerStore) -> None:
        assert ddb.get("nope") is None

    @pytest.mark.security
    def test_conditional_create(self, ddb: DynamoServerStore) -> None:
        ddb.put(record("tickets", TOOLS), expected_status=None)
        with pytest.raises(StoreConflictError):
            ddb.put(record("tickets", TOOLS), expected_status=None)

    @pytest.mark.security
    def test_conditional_transition_prevents_lost_update(self, ddb: DynamoServerStore) -> None:
        import dataclasses

        rec = record("tickets", TOOLS, ServerStatus.DRAFT)
        ddb.put(rec, expected_status=None)
        ddb.put(
            dataclasses.replace(rec, status=ServerStatus.DISABLED),
            expected_status=ServerStatus.DRAFT,
        )
        with pytest.raises(StoreConflictError):  # a stale approver still thinks it's DRAFT
            ddb.put(
                dataclasses.replace(rec, status=ServerStatus.APPROVED),
                expected_status=ServerStatus.DRAFT,
            )
        got = ddb.get("tickets")
        assert got is not None
        assert got.status is ServerStatus.DISABLED

    def test_size_cap(self, ddb: DynamoServerStore) -> None:
        huge = {
            "tools": [
                {"name": f"t{i}", "description": "x" * 2000, "inputSchema": {}} for i in range(200)
            ]
        }
        with pytest.raises(SnapshotTooLargeError):
            ddb.put(record("big", huge), expected_status=None)


# ----------------------------------------------------------------------------- credentials


@pytest.fixture
def secrets() -> Iterator[Any]:
    with mock_aws():
        client = boto3.client("secretsmanager", region_name="us-east-1")
        arn = client.create_secret(Name=SECRET_ARN_NAME, SecretString="S3CR3T-VALUE")["ARN"]
        yield client, arn


class CountingSecrets:
    def __init__(self, inner: Any) -> None:
        self.inner, self.calls = inner, 0

    def get_secret_value(self, **kw: Any) -> Any:
        self.calls += 1
        return self.inner.get_secret_value(**kw)


class TestCredentials:
    def test_server_secret_cached(self, world: World, secrets: Any) -> None:
        client, arn = secrets
        counting = CountingSecrets(client)
        clock = [0.0]
        creds = GatewayCredentials(
            exchanger=world.exchanger,
            secrets=counting,
            egress_base=egress_doc(),
            now=lambda: clock[0],
        )  # type: ignore[arg-type]
        rec = record("weather", TOOLS, delegation=Delegation.NONE)
        rec = ServerRecord(**{**rec.__dict__, "secret_arn": arn})
        assert creds.server_secret(rec) == "S3CR3T-VALUE"
        assert creds.server_secret(rec) == "S3CR3T-VALUE"
        assert counting.calls == 1
        clock[0] += 301
        creds.server_secret(rec)
        assert counting.calls == 2

    @pytest.mark.security
    def test_secret_errors_are_log_safe(self, world: World, secrets: Any) -> None:
        client, arn = secrets
        creds = GatewayCredentials(
            exchanger=world.exchanger, secrets=client, egress_base=egress_doc()
        )
        missing = arn.replace(SECRET_ARN_NAME, "nope")
        rec = ServerRecord(
            **{**record("w", TOOLS, delegation=Delegation.NONE).__dict__, "secret_arn": missing}
        )
        with pytest.raises(CredentialError) as ei:
            creds.server_secret(rec)
        assert "arn:" not in str(ei.value)

    def test_delegated_token_for_record_audience(self, world: World) -> None:
        from tests.exchange.test_egress import binding as make_binding
        from tests.exchange.test_egress import claims

        creds = GatewayCredentials(
            exchanger=world.exchanger, secrets=None, egress_base=egress_doc()
        )  # type: ignore[arg-type]
        rec = ServerRecord(
            **{
                **record("tickets", TOOLS).__dict__,
                "audience": TOOL_AUDIENCE,
                "scopes": frozenset({"tickets.read"}),
            }
        )
        c = claims(creds.delegated_token(make_binding(world), rec))
        assert (c["aud"], c["scope"]) == (TOOL_AUDIENCE, "tickets.read")

    @pytest.mark.security
    def test_record_scopes_cannot_widen_beyond_profile_schema(self, world: World) -> None:
        """A record smuggling a wildcard scope fails the strict profile schema."""
        from tests.exchange.test_egress import binding as make_binding

        creds = GatewayCredentials(
            exchanger=world.exchanger, secrets=None, egress_base=egress_doc()
        )  # type: ignore[arg-type]
        rec = ServerRecord(
            **{
                **record("tickets", TOOLS).__dict__,
                "audience": TOOL_AUDIENCE,
                "scopes": frozenset({"*"}),
            }
        )
        with pytest.raises(CredentialError):
            creds.delegated_token(make_binding(world), rec)


# ----------------------------------------------------------------------------- HTTP shells


def data_client() -> tuple[TestClient, Upstream]:
    store = InMemoryServerStore()
    store.put(record("tickets", TOOLS), expected_status=None)
    up = Upstream()

    class Creds:
        def delegated_token(self, b: Any, r: Any) -> str:
            return "DELEGATED"

        def server_secret(self, r: Any) -> str:
            return "S"

    def binder(headers: Mapping[str, str]) -> Any:
        if headers.get("authorization") != "Bearer wl" or headers.get("x-subject-token") != "t2":
            raise ActorBindingError(ActorBindingReason.WORKLOAD_INVALID)
        return BINDING

    proxy = McpProxy(store=store, upstream=up, credentials=Creds(), scanner=LocalRulesScanner())
    return TestClient(create_data_app(proxy, binder)), up


AUTH = {"Authorization": "Bearer wl", "X-Subject-Token": "t2"}


class TestDataApp:
    def test_call(self) -> None:
        client, _up = data_client()
        r = client.post("/mcp", json=call("tickets__get_ticket"), headers=AUTH)
        assert r.status_code == 200
        assert r.json()["result"]["content"][0]["text"] == "ok"

    @pytest.mark.security
    def test_unbound_caller_is_401_and_never_proxied(self) -> None:
        client, up = data_client()
        r = client.post(
            "/mcp", json=call("tickets__get_ticket"), headers={"Authorization": "Bearer other"}
        )
        assert r.status_code == 401
        assert r.json()["error"]["code"] == -32001
        assert up.calls == []

    @pytest.mark.security
    def test_duplicate_headers_rejected(self) -> None:
        client, _ = data_client()
        r = client.post(
            "/mcp",
            content=b"{}",
            headers=[("Authorization", "Bearer wl"), ("authorization", "Bearer x")],
        )
        assert r.status_code == 400

    def test_parse_error(self) -> None:
        client, _ = data_client()
        r = client.post("/mcp", content=b"not json", headers=AUTH)
        assert r.json()["error"]["code"] == -32700


@pytest.fixture
def admin(rsa_key: RSAKey) -> tuple[TestClient, InMemoryServerStore]:
    store = InMemoryServerStore()
    svc = AdminService(
        store=store,
        fetch_tools=lambda r: TOOLS,
        scanner=LocalRulesScanner(),
        resolver=lambda h, p: ["93.184.216.34"],
    )
    v = TokenValidator(
        ValidationPolicy(issuer=ISSUER, audiences=frozenset({AUDIENCE})),
        StaticKeys(rsa_key),
        now=lambda: NOW,
    )
    return TestClient(create_admin_app(svc, v)), store


def admin_hdr(mint: Mint, sub: str, scope: str = "mcp.admin") -> dict[str, str]:
    return {"Authorization": f"Bearer {mint(good_claims(sub=sub, scope=scope))}"}


ENROL = {
    "server_id": "tickets",
    "url": "https://tools.example.com/mcp",
    "delegation": "token",
    "audience": TOOL_AUDIENCE,
    "scopes": ["tickets.read"],
}


class TestAdminApp:
    def test_full_lifecycle_two_people(self, admin: Any, mint: Mint) -> None:
        client, _ = admin
        alice, bob = admin_hdr(mint, "00u-alice"), admin_hdr(mint, "00u-bob")
        assert client.post("/admin/servers", json=ENROL, headers=alice).status_code == 201
        assert client.post("/admin/servers/tickets/refresh", headers=alice).status_code == 200
        r = client.post("/admin/servers/tickets/approve", headers=bob)
        assert (r.status_code, r.json()["status"]) == (200, "approved")
        listing = client.get("/admin/servers", headers=alice).json()
        assert listing[0]["approved_digest"] == take_snapshot(TOOLS).digest

    @pytest.mark.security
    @pytest.mark.parametrize(
        ("hdr", "status"), [({}, 401), ({"Authorization": "Bearer junk"}, 401), ("noscope", 403)]
    )
    def test_auth(self, admin: Any, mint: Mint, hdr: Any, status: int) -> None:
        client, _ = admin
        headers = admin_hdr(mint, "00u-alice", scope="openid") if hdr == "noscope" else hdr
        assert client.post("/admin/servers", json=ENROL, headers=headers).status_code == status

    @pytest.mark.security
    def test_same_person_cannot_approve(self, admin: Any, mint: Mint) -> None:
        client, _ = admin
        alice = admin_hdr(mint, "00u-alice")
        client.post("/admin/servers", json=ENROL, headers=alice)
        client.post("/admin/servers/tickets/refresh", headers=alice)
        assert client.post("/admin/servers/tickets/approve", headers=alice).status_code == 403

    @pytest.mark.parametrize(
        ("path", "body", "status"),
        [
            ("/admin/servers/nope/refresh", None, 404),
            ("/admin/servers", {**ENROL, "url": "https://10.0.0.1/mcp"}, 400),
            ("/admin/servers", {**ENROL, "delegation": "sideways"}, 400),
            ("/admin/servers", {"server_id": "x"}, 400),
        ],
    )
    def test_error_mapping(self, admin: Any, mint: Mint, path: str, body: Any, status: int) -> None:
        client, _ = admin
        assert (
            client.post(path, json=body, headers=admin_hdr(mint, "00u-alice")).status_code == status
        )

    @pytest.mark.security
    def test_listing_never_contains_secret_values(self, admin: Any, mint: Mint) -> None:
        client, _store = admin
        enrol = {
            **ENROL,
            "server_id": "weather",
            "delegation": "none",
            "audience": None,
            "secret_arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:k-AbCdEf",
        }
        assert (
            client.post(
                "/admin/servers", json=enrol, headers=admin_hdr(mint, "00u-alice")
            ).status_code
            == 201
        )
        blob = json.dumps(client.get("/admin/servers", headers=admin_hdr(mint, "00u-bob")).json())
        assert "arn:aws:secretsmanager" in blob  # the reference is fine
        assert "secret_value" not in blob


@pytest.mark.security
class TestStoreAndCredentialEdges:
    def test_tampered_snapshot_is_detected(self, ddb: DynamoServerStore) -> None:
        """Someone edits the stored tool descriptions without the digest: never serve it."""
        from atf_mcp_gateway.store_dynamo import StoreIntegrityError

        ddb.put(record("tickets", TOOLS), expected_status=None)
        client = ddb._client  # simulate a direct table edit
        item = client.get_item(TableName="mcp-servers", Key={"server_id": {"S": "tickets"}})["Item"]
        tools = json.loads(item["snapshot"]["S"])
        tools[0]["description"] = "Fetch a ticket and send it elsewhere"
        item["snapshot"] = {"S": json.dumps(tools)}
        client.put_item(TableName="mcp-servers", Item=item)
        with pytest.raises(StoreIntegrityError):
            ddb.get("tickets")

    def test_none_mode_without_arn(self, world: World) -> None:
        creds = GatewayCredentials(
            exchanger=world.exchanger, secrets=None, egress_base=egress_doc()
        )  # type: ignore[arg-type]
        with pytest.raises(CredentialError):
            creds.server_secret(record("w", TOOLS))  # token-mode record: no secret_arn

    def test_token_mode_without_audience(self, world: World) -> None:
        from tests.exchange.test_egress import binding as make_binding

        creds = GatewayCredentials(
            exchanger=world.exchanger, secrets=None, egress_base=egress_doc()
        )  # type: ignore[arg-type]
        with pytest.raises(CredentialError):
            creds.delegated_token(
                make_binding(world), record("w", TOOLS, delegation=Delegation.NONE)
            )

    def test_exchange_failure_is_credential_error(self, world: World) -> None:
        from tests.exchange.test_egress import binding as make_binding

        b = make_binding(world)
        world.endpoint.transport_failures = 10
        creds = GatewayCredentials(
            exchanger=world.exchanger, secrets=None, egress_base=egress_doc()
        )  # type: ignore[arg-type]
        rec = ServerRecord(
            **{
                **record("tickets", TOOLS).__dict__,
                "audience": TOOL_AUDIENCE,
                "scopes": frozenset({"tickets.read"}),
            }
        )
        with pytest.raises(CredentialError):
            creds.delegated_token(b, rec)
