"""The bundle-version counter is atomic under concurrency, on a real DynamoDB engine (ED-14).

moto's in-process ``UpdateItem`` is not thread-safe, so a threaded moto test produced duplicate
versions on slow CI runners: a property of the emulator, not of DynamoDB's atomic ``ADD``. This
runs the same race against a throwaway DynamoDB Local, the exact image and command the compose
stack uses, bound to loopback on a random port. The stack's own instance stays on internal
networks only.
"""

from __future__ import annotations

import os
import pathlib
import subprocess
import threading
import time
from collections.abc import Iterator
from typing import Any

import pytest
import yaml

pytestmark = [
    pytest.mark.compose,
    pytest.mark.skipif(os.environ.get("ATF_COMPOSE") != "1", reason="needs docker (compose suite)"),
]

ROOT = pathlib.Path(__file__).resolve().parents[2]
# Same as compose: DynamoDB Local needs an exec /tmp for its native SQLite library (ED-9).
TMPFS = "/tmp:size=64m,mode=1777,exec"  # noqa: S108 - a tmpfs mount spec inside the container


def _docker(*args: str, check: bool = True) -> str:
    return subprocess.run(  # noqa: S603 - fixed argv, values from our own compose.yaml
        ["docker", *args],  # noqa: S607
        check=check,
        capture_output=True,
        text=True,
    ).stdout


@pytest.fixture(scope="module")
def ddb_endpoint() -> Iterator[str]:
    svc = yaml.safe_load((ROOT / "compose.yaml").read_text())["services"]["dynamodb-local"]
    cid = _docker(
        "run",
        "-d",
        "--rm",
        "--read-only",
        "--tmpfs",
        TMPFS,
        "-p",
        "127.0.0.1::8000",
        svc["image"],
        *svc["command"],
    ).strip()
    try:
        port = _docker("port", cid, "8000/tcp")
        endpoint = "http://" + port.splitlines()[0].strip()
        import boto3

        probe = boto3.client("dynamodb", endpoint_url=endpoint, **_local_creds())
        deadline = time.monotonic() + 60
        while True:
            try:
                probe.list_tables()
                break
            except Exception:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.5)
        yield endpoint
    finally:
        _docker("rm", "-f", cid, check=False)


def _local_creds() -> dict[str, Any]:
    # DynamoDB Local accepts any alphanumeric key (ED-9); these are not credentials.
    return {
        "region_name": "us-east-1",
        "aws_access_key_id": "local",
        "aws_secret_access_key": "local",
    }


@pytest.mark.security
def test_concurrent_counter_unique_on_dynamodb_local(ddb_endpoint: str) -> None:
    """TM-CP-07: bundle versions never repeat, even when publishers race."""
    import boto3
    from atf_agent_registry.store_dynamo import DynamoRegistryStore, ensure_local_table

    client = boto3.client("dynamodb", endpoint_url=ddb_endpoint, **_local_creds())
    ensure_local_table(client, "agents")
    got: list[int] = []
    lock = threading.Lock()

    def take() -> None:
        # One client per thread, as separate publisher processes would have.
        own = DynamoRegistryStore(
            boto3.client("dynamodb", endpoint_url=ddb_endpoint, **_local_creds()), "agents"
        )
        for _ in range(20):
            v = own.next_bundle_version()
            with lock:
                got.append(v)

    threads = [threading.Thread(target=take) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sorted(got) == list(range(1, 161))
