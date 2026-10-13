"""RegistryStore contract: in-memory and DynamoDB (moto) behave identically (ADR-0021 §5)."""

from __future__ import annotations

import dataclasses
import datetime as dt
from collections.abc import Iterator
from typing import Any

import boto3
import pytest
from atf_agent_registry.records import (
    AgentVersion,
    Approval,
    ApprovalRole,
    InMemoryRegistryStore,
    RegistryStore,
    State,
    StoreConflictError,
)
from atf_agent_registry.store_dynamo import (
    DynamoRegistryStore,
    StoreUnavailableError,
    ensure_local_table,
)
from botocore.stub import Stubber
from moto import mock_aws

from tests.registry.test_workflow import AGENT, T0, spec


def version(n: int = 1, **over: Any) -> AgentVersion:
    v = AgentVersion(
        agent_id=AGENT,
        version=n,
        spec=spec(),
        state=State.DRAFT,
        author="dave",
        created_at=T0,
        updated_at=T0,
    )
    return dataclasses.replace(v, **over)


def bump(v: AgentVersion, **over: Any) -> AgentVersion:
    return dataclasses.replace(v, rev=v.rev + 1, **over)


@pytest.fixture(params=["memory", "dynamo"])
def store(request: pytest.FixtureRequest) -> Iterator[RegistryStore]:
    if request.param == "memory":
        yield InMemoryRegistryStore()
        return
    with mock_aws():
        c = boto3.client("dynamodb", region_name="us-east-1")
        ensure_local_table(c, "agents")
        ensure_local_table(c, "agents")  # idempotent
        yield DynamoRegistryStore(c, "agents")


class TestContract:
    def test_put_get_roundtrip(self, store: RegistryStore) -> None:
        v = version(
            state=State.APPROVED,
            approvals=(Approval("bob", ApprovalRole.APPROVER, T0),),
            approved_at=T0,
            expires_at=T0 + dt.timedelta(days=90),
            decided_by=None,
        )
        store.put_new(v)
        assert store.get(AGENT, 1) == v
        assert store.get(AGENT, 2) is None
        assert store.get("other", 1) is None

    def test_put_new_is_create_only(self, store: RegistryStore) -> None:
        store.put_new(version())
        with pytest.raises(StoreConflictError):
            store.put_new(version(author="mallory"))
        got = store.get(AGENT, 1)
        assert got is not None
        assert got.author == "dave"

    def test_replace_conditional_on_state_and_rev(self, store: RegistryStore) -> None:
        v = version()
        store.put_new(v)
        v1 = bump(v, state=State.IN_REVIEW)
        store.replace(v1, expected=v)
        assert store.get(AGENT, 1) == v1
        with pytest.raises(StoreConflictError):  # stale rev
            store.replace(bump(v), expected=v)
        with pytest.raises(StoreConflictError):  # right rev, wrong state
            store.replace(bump(v1), expected=dataclasses.replace(v1, state=State.DRAFT))
        assert store.get(AGENT, 1) == v1

    def test_replace_missing_is_conflict(self, store: RegistryStore) -> None:
        v = version()
        with pytest.raises(StoreConflictError):
            store.replace(bump(v), expected=v)

    def test_replace_pair_is_atomic(self, store: RegistryStore) -> None:
        old = version(1, state=State.APPROVED)
        new = version(2, state=State.IN_REVIEW)
        store.put_new(old)
        store.put_new(new)
        stale_old = dataclasses.replace(old, rev=5)
        with pytest.raises(StoreConflictError):
            store.replace_pair(
                bump(new, state=State.APPROVED),
                expected=new,
                other=bump(stale_old, state=State.SUPERSEDED),
                other_expected=stale_old,
            )
        assert store.get(AGENT, 2) == new  # neither half written
        assert store.get(AGENT, 1) == old
        store.replace_pair(
            bump(new, state=State.APPROVED),
            expected=new,
            other=bump(old, state=State.SUPERSEDED),
            other_expected=old,
        )
        assert [v.state for v in store.versions(AGENT)] == [State.SUPERSEDED, State.APPROVED]

    def test_versions_ascending_and_agent_ids(self, store: RegistryStore) -> None:
        for n in (3, 1, 2):
            store.put_new(version(n))
        store.put_new(dataclasses.replace(version(1), agent_id="0oa-other"))
        assert [v.version for v in store.versions(AGENT)] == [1, 2, 3]
        assert sorted(store.agent_ids()) == sorted([AGENT, "0oa-other"])
        assert store.versions("nobody") == []


@pytest.mark.security
def test_dynamo_errors_are_unavailable() -> None:
    c = boto3.client(
        "dynamodb", region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="x"
    )
    stub = Stubber(c)
    stub.add_client_error(
        "get_item", service_error_code="InternalServerError", http_status_code=500
    )
    with stub, pytest.raises(StoreUnavailableError):
        DynamoRegistryStore(c, "agents").get(AGENT, 1)


@pytest.mark.security
def test_tampered_item_is_unavailable_not_trusted() -> None:
    """A stored spec that no longer validates is an integrity failure, never a partial record."""
    with mock_aws():
        c = boto3.client("dynamodb", region_name="us-east-1")
        ensure_local_table(c, "agents")
        store = DynamoRegistryStore(c, "agents")
        store.put_new(version())
        c.update_item(
            TableName="agents",
            Key={"agent_id": {"S": AGENT}, "version": {"N": "1"}},
            UpdateExpression="SET spec = :s",
            ExpressionAttributeValues={":s": {"S": '{"tier": "god-mode"}'}},
        )
        with pytest.raises(StoreUnavailableError):
            store.get(AGENT, 1)


def _stubbed() -> tuple[Any, Stubber]:
    c = boto3.client(
        "dynamodb", region_name="us-east-1", aws_access_key_id="x", aws_secret_access_key="x"
    )
    return c, Stubber(c)


class TestDynamoEdges:
    def test_decided_by_roundtrip(self) -> None:
        with mock_aws():
            c = boto3.client("dynamodb", region_name="us-east-1")
            ensure_local_table(c, "agents")
            s = DynamoRegistryStore(c, "agents")
            v = version(state=State.REVOKED, decided_by="carol")
            s.put_new(v)
            assert s.get(AGENT, 1) == v

    def test_pagination(self) -> None:
        from atf_agent_registry.store_dynamo import to_item

        c, stub = _stubbed()
        page = {"agent_id": {"S": AGENT}, "version": {"N": "1"}}
        stub.add_response("query", {"Items": [to_item(version(1))], "LastEvaluatedKey": page})
        stub.add_response("query", {"Items": [to_item(version(2))]})
        stub.add_response("scan", {"Items": [{"agent_id": {"S": "a"}}], "LastEvaluatedKey": page})
        stub.add_response("scan", {"Items": [{"agent_id": {"S": "b"}}]})
        with stub:
            s = DynamoRegistryStore(c, "agents")
            assert [v.version for v in s.versions(AGENT)] == [1, 2]
            assert s.agent_ids() == ["a", "b"]

    @pytest.mark.security
    @pytest.mark.parametrize("op", ["query", "scan"])
    def test_read_errors_unavailable(self, op: str) -> None:
        c, stub = _stubbed()
        stub.add_client_error(op, service_error_code="InternalServerError", http_status_code=500)
        s = DynamoRegistryStore(c, "agents")
        with stub, pytest.raises(StoreUnavailableError):
            s.versions(AGENT) if op == "query" else s.agent_ids()

    @pytest.mark.security
    def test_write_error_unavailable_not_conflict(self) -> None:
        c, stub = _stubbed()
        stub.add_client_error("put_item", service_error_code="InternalServerError")
        with stub, pytest.raises(StoreUnavailableError):
            DynamoRegistryStore(c, "agents").put_new(version())

    @pytest.mark.security
    def test_transaction_cancelled_for_other_reason_is_unavailable(self) -> None:
        """Only a failed *condition* is a race (409); throttling etc. must not look like one."""
        c, stub = _stubbed()
        stub.add_client_error(
            "transact_write_items",
            service_error_code="TransactionCanceledException",
            response_meta={},
        )
        v1, v2 = version(1, state=State.APPROVED), version(2, state=State.IN_REVIEW)
        with stub, pytest.raises(StoreUnavailableError):
            DynamoRegistryStore(c, "agents").replace_pair(
                bump(v2), expected=v2, other=bump(v1), other_expected=v1
            )

    @pytest.mark.security
    def test_unreachable_endpoint(self) -> None:
        from botocore.exceptions import EndpointConnectionError

        class Down:
            def put_item(self, **_: Any) -> None:
                raise EndpointConnectionError(endpoint_url="https://dynamodb.invalid")

        with pytest.raises(StoreUnavailableError):
            DynamoRegistryStore(Down(), "agents").put_new(version())  # type: ignore[arg-type]
