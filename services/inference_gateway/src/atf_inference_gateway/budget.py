"""Per-agent daily token budgets with atomic reservations (ADR-0019 §5, TM-INF-02)."""

from __future__ import annotations

import math
import threading
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any, Protocol

from botocore.exceptions import BotoCoreError, ClientError

if TYPE_CHECKING:
    from mypy_boto3_dynamodb import DynamoDBClient


class BudgetUnavailableError(Exception):
    """The budget store could not answer. Callers must deny (fail closed)."""


class BudgetStore(Protocol):
    def reserve(self, agent: str, day: str, amount: int, limit: int) -> bool:
        """Atomically add ``amount`` iff the result stays <= ``limit``. False if it wouldn't."""
        ...

    def adjust(self, agent: str, day: str, delta: int) -> None:
        """Settle (positive/negative delta). Never fails the request once the call happened."""
        ...


def estimate_tokens(messages: Sequence[Mapping[str, Any]], max_tokens: int) -> int:
    """Conservative pre-call estimate without a tokenizer download: ceil(chars/4) + max_tokens."""
    chars = sum(len(str(m.get("content", ""))) for m in messages)
    return math.ceil(chars / 4) + max_tokens


class InMemoryBudgetStore:
    def __init__(self) -> None:
        self._used: dict[tuple[str, str], int] = {}
        self._lock = threading.Lock()

    def reserve(self, agent: str, day: str, amount: int, limit: int) -> bool:
        with self._lock:
            current = self._used.get((agent, day), 0)
            if amount > limit or current + amount > limit:
                return False
            self._used[(agent, day)] = current + amount
            return True

    def adjust(self, agent: str, day: str, delta: int) -> None:
        with self._lock:
            self._used[(agent, day)] = max(0, self._used.get((agent, day), 0) + delta)

    def used(self, agent: str, day: str) -> int:
        return self._used.get((agent, day), 0)


class DynamoBudgetStore:
    """Item per ``agent#day``; reservation is a conditional ``ADD`` (no overspend races)."""

    def __init__(self, client: DynamoDBClient, table_name: str) -> None:
        self._client, self._table = client, table_name

    def reserve(self, agent: str, day: str, amount: int, limit: int) -> bool:
        if amount > limit:  # also stops attribute_not_exists() admitting an oversized first spend
            return False
        try:
            self._client.update_item(
                TableName=self._table,
                Key={"pk": {"S": f"{agent}#{day}"}},
                UpdateExpression="ADD used :n",
                ConditionExpression="attribute_not_exists(used) OR used <= :room",
                ExpressionAttributeValues={
                    ":n": {"N": str(amount)},
                    ":room": {"N": str(limit - amount)},
                },
            )
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                return False
            raise BudgetUnavailableError("budget store error") from None
        except BotoCoreError:
            raise BudgetUnavailableError("budget store unreachable") from None
        return True

    def adjust(self, agent: str, day: str, delta: int) -> None:
        try:
            self._client.update_item(
                TableName=self._table,
                Key={"pk": {"S": f"{agent}#{day}"}},
                UpdateExpression="ADD used :d",
                ExpressionAttributeValues={":d": {"N": str(delta)}},
            )
        except (ClientError, BotoCoreError):
            raise BudgetUnavailableError("budget store error") from None
