"""Circuit breaker state machine (ADR-0014 §4, TM-EXC-07)."""

from __future__ import annotations

import pytest

from trustkit.breaker import BreakerRegistry, CircuitBreaker, CircuitState


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def breaker(
    clock: Clock, transitions: list[tuple[str, CircuitState, CircuitState]] | None = None
) -> CircuitBreaker:
    return CircuitBreaker(
        "idp",
        failure_threshold=3,
        cooldown_s=30,
        now=clock,
        on_transition=(lambda n, a, b: transitions.append((n, a, b)))
        if transitions is not None
        else None,
    )


class TestStateMachine:
    def test_starts_closed_and_allows(self) -> None:
        b = breaker(Clock())
        assert b.state is CircuitState.CLOSED
        assert b.allow()

    def test_opens_after_consecutive_failures(self) -> None:
        b = breaker(Clock())
        for _ in range(3):
            assert b.allow()
            b.record_failure()
        assert b.state is CircuitState.OPEN
        assert not b.allow()

    def test_success_resets_the_count(self) -> None:
        """Consecutive, not cumulative: an intermittent blip shouldn't trip the breaker."""
        b = breaker(Clock())
        for _ in range(10):
            b.record_failure()
            b.record_failure()
            b.record_success()
        assert b.state is CircuitState.CLOSED

    def test_half_open_admits_exactly_one_probe(self) -> None:
        clock = Clock()
        b = breaker(clock)
        for _ in range(3):
            b.record_failure()
        clock.t += 29.9
        assert not b.allow()
        clock.t += 0.2
        assert b.allow()
        assert b.state is CircuitState.HALF_OPEN
        assert not b.allow(), "second concurrent probe must be refused"

    def test_probe_success_closes(self) -> None:
        clock = Clock()
        b = breaker(clock)
        for _ in range(3):
            b.record_failure()
        clock.t += 31
        assert b.allow()
        b.record_success()
        assert b.state is CircuitState.CLOSED
        assert b.allow()

    def test_probe_failure_reopens_with_fresh_cooldown(self) -> None:
        clock = Clock()
        b = breaker(clock)
        for _ in range(3):
            b.record_failure()
        clock.t += 31
        assert b.allow()
        b.record_failure()
        assert b.state is CircuitState.OPEN
        clock.t += 29
        assert not b.allow()
        clock.t += 2
        assert b.allow()

    def test_release_probe_frees_slot_without_closing(self) -> None:
        """A probe that never reached the dependency proves nothing either way."""
        clock = Clock()
        b = breaker(clock)
        for _ in range(3):
            b.record_failure()
        clock.t += 31
        assert b.allow()
        b.release_probe()
        assert b.state is CircuitState.HALF_OPEN
        assert b.allow(), "slot must be free for the next probe"

    def test_transitions_reported(self) -> None:
        clock, seen = Clock(), []  # type: ignore[var-annotated]
        b = breaker(clock, seen)
        for _ in range(3):
            b.record_failure()
        clock.t += 31
        b.allow()
        b.record_success()
        assert [(a, z) for _, a, z in seen] == [
            (CircuitState.CLOSED, CircuitState.OPEN),
            (CircuitState.OPEN, CircuitState.HALF_OPEN),
            (CircuitState.HALF_OPEN, CircuitState.CLOSED),
        ]

    def test_transition_callback_failure_does_not_break_breaker(self) -> None:
        def boom(*_: object) -> None:
            raise RuntimeError("audit down")

        b = CircuitBreaker("idp", failure_threshold=1, now=Clock(), on_transition=boom)
        b.record_failure()
        assert b.state is CircuitState.OPEN

    @pytest.mark.parametrize("bad", [{"failure_threshold": 0}, {"cooldown_s": 0}])
    def test_rejects_invalid_config(self, bad: dict[str, float]) -> None:
        with pytest.raises(ValueError, match="breaker"):
            CircuitBreaker("x", **bad)  # type: ignore[arg-type]


class TestRegistry:
    def test_one_breaker_per_key(self) -> None:
        r = BreakerRegistry(failure_threshold=1, now=Clock())
        r.get("https://a/token").record_failure()
        assert r.get("https://a/token").state is CircuitState.OPEN
        assert r.get("https://b/token").state is CircuitState.CLOSED
        assert r.get("https://a/token") is r.get("https://a/token")
