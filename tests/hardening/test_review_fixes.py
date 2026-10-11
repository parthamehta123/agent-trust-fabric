"""Regression tests for the post-Phase-2 review (R1-R3)."""

from __future__ import annotations

import asyncio
import threading
import time
from collections.abc import Mapping
from typing import Any

import httpx
import pytest
from atf_agent_runtime.app import create_app as runtime_app
from atf_agent_runtime.runtime import AgentRuntime, InvocationResult

from gateway_emulator.app import create_app as gateway_app
from gateway_emulator.core import GatewayResponse
from trustkit.profiles import ScannerFailureMode
from trustkit.scanning import Direction, ScanResult, Verdict, scan_with_policy

SLOW_S = 0.3
N = 5


def _concurrent_wall_time(app: Any, path: str) -> float:
    async def run() -> float:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="https://t") as c:
            start = time.perf_counter()
            await asyncio.gather(*(c.post(path, content=b"{}") for _ in range(N)))
            return time.perf_counter() - start

    return asyncio.run(run())


@pytest.mark.security
class TestR1NoBlockingInEventLoop:
    """TM-ING-05: a slow downstream call must not serialise every other request."""

    def test_runtime_shell(self) -> None:
        class Slow:
            def invoke(self, headers: Mapping[str, str], body: bytes) -> InvocationResult:
                time.sleep(SLOW_S)
                return InvocationResult(200, {"Content-Type": "application/json"}, b"{}")

        elapsed = _concurrent_wall_time(runtime_app(Slow()), "/invocations")  # type: ignore[arg-type]
        assert elapsed < SLOW_S * N * 0.6, f"requests serialised: {elapsed:.2f}s"

    def test_gateway_shell(self) -> None:
        class Slow:
            def invoke(self, *a: Any, **k: Any) -> GatewayResponse:
                time.sleep(SLOW_S)
                return GatewayResponse(200, b"{}")

        elapsed = _concurrent_wall_time(gateway_app(Slow()), "/agent-alpha/invocations")  # type: ignore[arg-type]
        assert elapsed < SLOW_S * N * 0.6, f"requests serialised: {elapsed:.2f}s"


@pytest.mark.security
class TestR2BoundedObservability:
    def test_runtime_principal_history_is_bounded(self) -> None:
        from trustkit.resource import Principal

        rt = AgentRuntime.__new__(AgentRuntime)
        AgentRuntime.__init__(rt, authorizer=None, agent=lambda p, r: {})  # type: ignore[arg-type]
        for i in range(500):
            rt.principals_seen.append(Principal(f"u{i}", "c", frozenset(), None))
        assert len(rt.principals_seen) <= 64

    def test_emulator_call_history_is_bounded(self) -> None:
        from gateway_emulator.core import GatewayEmulator, InboundJwt

        gw = GatewayEmulator(
            gateway_arn="arn:aws:bedrock-agentcore:us-east-1:123456789012:gateway/gw-x",
            inbound=InboundJwt("https://i", frozenset({"a"}), lambda: {"keys": []}),
            targets={},
        )
        for _ in range(1000):
            gw.invoke("/x/invocations", {}, b"")
        assert len(gw.calls) <= 256


@pytest.mark.security
class TestR3ScannerThreadsAreBounded:
    """A hung scanner must not grow threads without bound; saturation follows the fail mode."""

    def test_saturation_fails_fast_then_recovers(self) -> None:
        release = threading.Event()
        calls = 0

        class Hung:
            def scan(self, text: str, *, direction: Direction) -> ScanResult:
                nonlocal calls
                calls += 1
                release.wait(5)
                return ScanResult(Verdict.ALLOW)

        limiter = threading.BoundedSemaphore(2)
        for _ in range(2):
            o = scan_with_policy(
                Hung(),
                "x",
                direction=Direction.REQUEST,
                failure_mode=ScannerFailureMode.CLOSED,
                timeout_s=0.05,
                limiter=limiter,
            )
            assert o.failure == "timeout"
        o = scan_with_policy(
            Hung(),
            "x",
            direction=Direction.REQUEST,
            failure_mode=ScannerFailureMode.CLOSED,
            timeout_s=0.05,
            limiter=limiter,
        )
        assert (o.failure, o.result.verdict, calls) == ("saturated", Verdict.BLOCK, 2)

        release.set()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            o = scan_with_policy(
                Hung(),
                "x",
                direction=Direction.REQUEST,
                failure_mode=ScannerFailureMode.CLOSED,
                timeout_s=1,
                limiter=limiter,
            )
            if o.failure is None:
                break
            time.sleep(0.05)
        assert o.failure is None, "slots must be released when hung scans finish"
