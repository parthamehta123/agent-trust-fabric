"""Consecutive-failure circuit breaker for IdP endpoints (ADR-0014 §4, TM-EXC-07).

States::

    CLOSED --(failure_threshold consecutive failures)--> OPEN
    OPEN   --(cooldown elapsed, next allow())----------> HALF_OPEN (exactly one probe admitted)
    HALF_OPEN --probe success--> CLOSED
    HALF_OPEN --probe failure--> OPEN (cooldown restarts)

Only *dependency* failures count (transport errors, 5xx, 429). The caller decides what is a
failure. A 4xx policy answer means the IdP is healthy and must be recorded as a success.
"""

from __future__ import annotations

import contextlib
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

DEFAULT_FAILURE_THRESHOLD: Final = 5
DEFAULT_COOLDOWN_S: Final = 30.0


class CircuitState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


Transition = Callable[[str, CircuitState, CircuitState], None]
"""(breaker name, old state, new state) -> None. Used to audit transitions."""


@dataclass
class CircuitBreaker:
    name: str
    failure_threshold: int = DEFAULT_FAILURE_THRESHOLD
    cooldown_s: float = DEFAULT_COOLDOWN_S
    now: Callable[[], float] = time.monotonic
    on_transition: Transition | None = field(default=None, repr=False)
    _state: CircuitState = field(default=CircuitState.CLOSED, init=False)
    _failures: int = field(default=0, init=False)
    _opened_at: float = field(default=0.0, init=False)
    _probe_in_flight: bool = field(default=False, init=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.failure_threshold < 1 or self.cooldown_s <= 0:
            raise ValueError("breaker threshold must be >= 1 and cooldown > 0")

    @property
    def state(self) -> CircuitState:
        return self._state

    def allow(self) -> bool:
        """May a call proceed? In HALF_OPEN, True exactly once until the probe is recorded."""
        with self._lock:
            if self._state is CircuitState.CLOSED:
                return True
            if self._state is CircuitState.OPEN:
                if self.now() - self._opened_at < self.cooldown_s:
                    return False
                self._transition(CircuitState.HALF_OPEN)
                self._probe_in_flight = True
                return True
            if self._probe_in_flight:
                return False
            self._probe_in_flight = True
            return True

    def record_success(self) -> None:
        with self._lock:
            self._failures = 0
            self._probe_in_flight = False
            if self._state is not CircuitState.CLOSED:
                self._transition(CircuitState.CLOSED)

    def release_probe(self) -> None:
        """The admitted call never reached the dependency (e.g. our own signing failed).

        Frees the half-open probe slot without claiming anything about the dependency's health.
        Recording success would close the breaker on no evidence; recording nothing would wedge it.
        """
        with self._lock:
            self._probe_in_flight = False

    def record_failure(self) -> None:
        with self._lock:
            if self._state is CircuitState.HALF_OPEN:
                self._open()
            elif self._state is CircuitState.CLOSED:
                self._failures += 1
                if self._failures >= self.failure_threshold:
                    self._open()

    def _open(self) -> None:
        self._opened_at = self.now()
        self._probe_in_flight = False
        self._failures = 0
        self._transition(CircuitState.OPEN)

    def _transition(self, new: CircuitState) -> None:
        old, self._state = self._state, new
        if self.on_transition is not None:
            # An observer (e.g. audit) failing must never change breaker behaviour.
            with contextlib.suppress(Exception):
                self.on_transition(self.name, old, new)


@dataclass
class BreakerRegistry:
    """One breaker per key (token endpoint URL), created on first use with shared settings."""

    failure_threshold: int = DEFAULT_FAILURE_THRESHOLD
    cooldown_s: float = DEFAULT_COOLDOWN_S
    now: Callable[[], float] = time.monotonic
    on_transition: Transition | None = field(default=None, repr=False)
    _breakers: dict[str, CircuitBreaker] = field(default_factory=dict, init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def get(self, key: str) -> CircuitBreaker:
        with self._lock:
            b = self._breakers.get(key)
            if b is None:
                b = CircuitBreaker(
                    key,
                    failure_threshold=self.failure_threshold,
                    cooldown_s=self.cooldown_s,
                    now=self.now,
                    on_transition=self.on_transition,
                )
                self._breakers[key] = b
            return b
