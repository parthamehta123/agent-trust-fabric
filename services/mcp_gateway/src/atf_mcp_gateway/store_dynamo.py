"""DynamoDB ``ServerStore`` (ADR-0018 §3).

One item per server (PK ``server_id``). Creates use ``attribute_not_exists``; transitions use a
condition on the expected status, so concurrent admin actions can't lose updates. The snapshot is
inline as canonical JSON; records over ``MAX_ITEM_BYTES`` are refused before the write.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, Final

from botocore.exceptions import ClientError

from atf_mcp_gateway.servers import (
    Delegation,
    ServerRecord,
    ServerStatus,
    SnapshotTooLargeError,
    StoreConflictError,
)
from atf_mcp_gateway.snapshot import take_snapshot

if TYPE_CHECKING:
    from mypy_boto3_dynamodb import DynamoDBClient

MAX_ITEM_BYTES: Final = 300_000


class StoreIntegrityError(Exception):
    """A stored snapshot no longer matches its stored digest (corruption or tampering)."""


_OPTIONAL = ("audience", "secret_arn", "approved_by", "approved_digest")


def to_item(record: ServerRecord) -> dict[str, Any]:
    item: dict[str, Any] = {
        "server_id": {"S": record.server_id},
        "url": {"S": record.url},
        "delegation": {"S": record.delegation.value},
        "scopes": {"S": json.dumps(sorted(record.scopes))},
        "status": {"S": record.status.value},
        "enrolled_by": {"S": record.enrolled_by},
    }
    for name in _OPTIONAL:
        value = getattr(record, name)
        if value is not None:
            item[name] = {"S": value}
    if record.current is not None:
        item["snapshot"] = {"S": json.dumps(list(record.current.tools), sort_keys=True)}
        item["snapshot_digest"] = {"S": record.current.digest}
    if len(json.dumps(item)) > MAX_ITEM_BYTES:
        raise SnapshotTooLargeError("server record exceeds the storage budget")
    return item


def from_item(item: dict[str, Any]) -> ServerRecord:
    def opt(name: str) -> str | None:
        return item[name]["S"] if name in item else None

    current = None
    if "snapshot" in item:
        current = take_snapshot({"tools": json.loads(item["snapshot"]["S"])})
        if current.digest != item["snapshot_digest"]["S"]:
            raise StoreIntegrityError("stored snapshot does not match its digest")
    return ServerRecord(
        server_id=item["server_id"]["S"],
        url=item["url"]["S"],
        delegation=Delegation(item["delegation"]["S"]),
        audience=opt("audience"),
        scopes=frozenset(json.loads(item["scopes"]["S"])),
        secret_arn=opt("secret_arn"),
        status=ServerStatus(item["status"]["S"]),
        enrolled_by=item["enrolled_by"]["S"],
        approved_by=opt("approved_by"),
        approved_digest=opt("approved_digest"),
        current=current,
    )


class DynamoServerStore:
    def __init__(self, client: DynamoDBClient, table_name: str) -> None:
        self._client, self._table = client, table_name

    def get(self, server_id: str) -> ServerRecord | None:
        resp = self._client.get_item(
            TableName=self._table, Key={"server_id": {"S": server_id}}, ConsistentRead=True
        )
        item = resp.get("Item")
        return None if item is None else from_item(dict(item))

    def put(self, record: ServerRecord, *, expected_status: ServerStatus | None) -> None:
        item = to_item(record)
        try:
            if expected_status is None:
                self._client.put_item(
                    TableName=self._table,
                    Item=item,
                    ConditionExpression="attribute_not_exists(server_id)",
                )
            else:
                self._client.put_item(
                    TableName=self._table,
                    Item=item,
                    ConditionExpression="#s = :expected",
                    ExpressionAttributeNames={"#s": "status"},
                    ExpressionAttributeValues={":expected": {"S": expected_status.value}},
                )
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                raise StoreConflictError("record changed underneath us") from None
            raise

    def list(self) -> list[ServerRecord]:
        records: list[ServerRecord] = []
        kwargs: dict[str, Any] = {"TableName": self._table, "ConsistentRead": True}
        while True:
            page = self._client.scan(**kwargs)
            records.extend(from_item(dict(i)) for i in page.get("Items", []))
            if "LastEvaluatedKey" not in page:
                return records
            kwargs["ExclusiveStartKey"] = page["LastEvaluatedKey"]
