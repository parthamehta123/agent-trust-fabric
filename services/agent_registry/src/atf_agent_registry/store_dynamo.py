"""DynamoDB ``RegistryStore`` (ADR-0021 §5): PK ``agent_id``, SK ``version``; every write
conditional; approve + supersede in one transaction. A stored item that fails validation is an
integrity failure (``StoreUnavailableError``), never a partial record."""

from __future__ import annotations

import datetime as dt
import json
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any, Final

from botocore.exceptions import BotoCoreError, ClientError
from pydantic import ValidationError

from atf_agent_registry.records import (
    AgentSpec,
    AgentVersion,
    Approval,
    ApprovalRole,
    State,
    StoreConflictError,
    StoreUnavailableError,
    canonical_spec_json,
)

if TYPE_CHECKING:
    from mypy_boto3_dynamodb import DynamoDBClient

__all__ = ["DynamoRegistryStore", "StoreUnavailableError", "ensure_local_table"]

_CONDITION: Final = "#s = :s AND #r = :r"
_COUNTER_ID: Final = "#bundle"
"""Reserved item: '#' can never start a valid agent id."""
_NAMES: Final = {"#s": "state", "#r": "rev"}


def _ts(t: dt.datetime | None) -> dict[str, str] | None:
    return None if t is None else {"S": t.isoformat()}


def to_item(v: AgentVersion) -> dict[str, Any]:
    item: dict[str, Any] = {
        "agent_id": {"S": v.agent_id},
        "version": {"N": str(v.version)},
        "rev": {"N": str(v.rev)},
        "state": {"S": v.state.value},
        "author": {"S": v.author},
        "spec": {"S": canonical_spec_json(v.spec)},
        "approvals": {
            "S": json.dumps(
                [
                    {"subject": a.subject, "role": a.role.value, "at": a.at.isoformat()}
                    for a in v.approvals
                ]
            )
        },
        "created_at": {"S": v.created_at.isoformat()},
        "updated_at": {"S": v.updated_at.isoformat()},
    }
    for name in ("approved_at", "expires_at"):
        value = _ts(getattr(v, name))
        if value is not None:
            item[name] = value
    if v.decided_by is not None:
        item["decided_by"] = {"S": v.decided_by}
    return item


def from_item(item: dict[str, Any]) -> AgentVersion:
    try:

        def opt_ts(name: str) -> dt.datetime | None:
            return dt.datetime.fromisoformat(item[name]["S"]) if name in item else None

        return AgentVersion(
            agent_id=item["agent_id"]["S"],
            version=int(item["version"]["N"]),
            rev=int(item["rev"]["N"]),
            state=State(item["state"]["S"]),
            author=item["author"]["S"],
            spec=AgentSpec.model_validate_json(item["spec"]["S"]),
            approvals=tuple(
                Approval(a["subject"], ApprovalRole(a["role"]), dt.datetime.fromisoformat(a["at"]))
                for a in json.loads(item["approvals"]["S"])
            ),
            created_at=dt.datetime.fromisoformat(item["created_at"]["S"]),
            updated_at=dt.datetime.fromisoformat(item["updated_at"]["S"]),
            approved_at=opt_ts("approved_at"),
            expires_at=opt_ts("expires_at"),
            decided_by=item["decided_by"]["S"] if "decided_by" in item else None,
        )
    except (KeyError, TypeError, ValueError, ValidationError):
        raise StoreUnavailableError("stored record failed validation") from None


def _key(agent_id: str, version: int) -> dict[str, Any]:
    return {"agent_id": {"S": agent_id}, "version": {"N": str(version)}}


def _expect(expected: AgentVersion) -> dict[str, Any]:
    return {":s": {"S": expected.state.value}, ":r": {"N": str(expected.rev)}}


class DynamoRegistryStore:
    def __init__(self, client: DynamoDBClient, table_name: str) -> None:
        self._c, self._t = client, table_name

    def put_new(self, v: AgentVersion) -> None:
        self._write(
            lambda: self._c.put_item(
                TableName=self._t,
                Item=to_item(v),
                ConditionExpression="attribute_not_exists(agent_id)",
            )
        )

    def replace(self, v: AgentVersion, *, expected: AgentVersion) -> None:
        self._write(
            lambda: self._c.put_item(
                TableName=self._t,
                Item=to_item(v),
                ConditionExpression=_CONDITION,
                ExpressionAttributeNames=_NAMES,
                ExpressionAttributeValues=_expect(expected),
            )
        )

    def replace_pair(
        self,
        v: AgentVersion,
        *,
        expected: AgentVersion,
        other: AgentVersion,
        other_expected: AgentVersion,
    ) -> None:
        def put(item: AgentVersion, exp: AgentVersion) -> dict[str, Any]:
            return {
                "Put": {
                    "TableName": self._t,
                    "Item": to_item(item),
                    "ConditionExpression": _CONDITION,
                    "ExpressionAttributeNames": _NAMES,
                    "ExpressionAttributeValues": _expect(exp),
                }
            }

        self._write(
            lambda: self._c.transact_write_items(
                TransactItems=[put(v, expected), put(other, other_expected)]  # type: ignore[list-item]
            )
        )

    def get(self, agent_id: str, version: int) -> AgentVersion | None:
        try:
            r = self._c.get_item(
                TableName=self._t, Key=_key(agent_id, version), ConsistentRead=True
            )
        except (ClientError, BotoCoreError):
            raise StoreUnavailableError("registry store unreachable") from None
        item = r.get("Item")
        return None if item is None else from_item(item)

    def versions(self, agent_id: str) -> Sequence[AgentVersion]:
        out: list[AgentVersion] = []
        kwargs: dict[str, Any] = {
            "TableName": self._t,
            "KeyConditionExpression": "agent_id = :a",
            "ExpressionAttributeValues": {":a": {"S": agent_id}},
            "ConsistentRead": True,
        }
        try:
            while True:
                r = self._c.query(**kwargs)
                out.extend(from_item(i) for i in r.get("Items", []))
                if "LastEvaluatedKey" not in r:
                    break
                kwargs["ExclusiveStartKey"] = r["LastEvaluatedKey"]
        except (ClientError, BotoCoreError):
            raise StoreUnavailableError("registry store unreachable") from None
        return sorted(out, key=lambda v: v.version)

    def agent_ids(self) -> Sequence[str]:
        ids: set[str] = set()
        kwargs: dict[str, Any] = {"TableName": self._t, "ProjectionExpression": "agent_id"}
        try:
            while True:
                r = self._c.scan(**kwargs)
                ids.update(
                    i["agent_id"]["S"]
                    for i in r.get("Items", [])
                    if i["agent_id"]["S"] != _COUNTER_ID
                )
                if "LastEvaluatedKey" not in r:
                    break
                kwargs["ExclusiveStartKey"] = r["LastEvaluatedKey"]
        except (ClientError, BotoCoreError):
            raise StoreUnavailableError("registry store unreachable") from None
        return sorted(ids)

    def next_bundle_version(self) -> int:
        """Atomic ``ADD`` on the reserved item ``agent_id = "#bundle"`` (never a valid id)."""
        try:
            r = self._c.update_item(
                TableName=self._t,
                Key=_key(_COUNTER_ID, 0),
                UpdateExpression="ADD bundle_version :one",
                ExpressionAttributeValues={":one": {"N": "1"}},
                ReturnValues="UPDATED_NEW",
            )
            return int(r["Attributes"]["bundle_version"]["N"])
        except (ClientError, BotoCoreError, KeyError, ValueError):
            raise StoreUnavailableError("bundle counter unavailable") from None

    @staticmethod
    def _write(op: Any) -> None:
        try:
            op()
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code")
            if code == "ConditionalCheckFailedException":
                raise StoreConflictError from None
            if code == "TransactionCanceledException":
                reasons = e.response.get("CancellationReasons", [])
                if any(r.get("Code") == "ConditionalCheckFailed" for r in reasons):
                    raise StoreConflictError from None
            raise StoreUnavailableError("registry store error") from None
        except BotoCoreError:
            raise StoreUnavailableError("registry store unreachable") from None


def ensure_local_table(client: DynamoDBClient, table_name: str) -> None:
    """Local stack only; Terraform owns the table elsewhere."""
    try:
        client.describe_table(TableName=table_name)
    except client.exceptions.ResourceNotFoundException:
        client.create_table(
            TableName=table_name,
            KeySchema=[
                {"AttributeName": "agent_id", "KeyType": "HASH"},
                {"AttributeName": "version", "KeyType": "RANGE"},
            ],
            AttributeDefinitions=[
                {"AttributeName": "agent_id", "AttributeType": "S"},
                {"AttributeName": "version", "AttributeType": "N"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )
        client.get_waiter("table_exists").wait(TableName=table_name)
