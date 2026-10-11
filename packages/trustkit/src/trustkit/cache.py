"""Process-local T2 cache (ADR-0003 as amended by ADR-0011).

* Key: ``SHA-256(AT.jti ‖ IDT.jti ‖ sub ‖ audience ‖ profile_id)``. ``None`` (meaning "do not
  cache") if either jti is missing. There is never a fallback to a weaker key.
* TTL: ``min(exp - refresh_margin_s, now + max_ttl_s)``. Tokens already inside the margin
  are not stored.
* LRU-bounded so a flood of distinct sessions cannot exhaust memory.
* Values are never part of any ``repr``.

Threat-model refs: TM-EXC-03, TM-EXC-04.
"""

from __future__ import annotations

import hashlib
import threading
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Final

DEFAULT_MAX_ENTRIES: Final = 1024
DEFAULT_MAX_TTL_S: Final = 300
DEFAULT_REFRESH_MARGIN_S: Final = 30


def cache_key(
    *, at_jti: str | None, idt_jti: str | None, subject: str, audience: str, profile_id: str
) -> str | None:
    if not at_jti or not idt_jti:
        return None
    h = hashlib.sha256()
    for part in (at_jti, idt_jti, subject, audience, profile_id):
        raw = part.encode("utf-8")
        h.update(len(raw).to_bytes(4, "big"))  # length-prefix: ("ab","c") != ("a","bc")
        h.update(raw)
    return h.hexdigest()


@dataclass
class TokenCache[V]:
    max_entries: int = DEFAULT_MAX_ENTRIES
    max_ttl_s: int = DEFAULT_MAX_TTL_S
    refresh_margin_s: int = DEFAULT_REFRESH_MARGIN_S
    now: Callable[[], int] = field(default=lambda: int(time.time()))
    _entries: OrderedDict[str, tuple[int, V]] = field(
        default_factory=OrderedDict, init=False, repr=False
    )
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def __post_init__(self) -> None:
        if self.max_entries <= 0 or self.max_ttl_s <= 0 or self.refresh_margin_s < 0:
            raise ValueError("cache bounds must be positive")

    def get(self, key: str) -> V | None:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            expires_at, value = entry
            if self.now() >= expires_at:
                del self._entries[key]
                return None
            self._entries.move_to_end(key)
            return value

    def put(self, key: str, value: V, *, exp: int) -> bool:
        """Store until ``min(exp - margin, now + max_ttl)``. Returns False if not stored."""
        now = self.now()
        expires_at = min(exp - self.refresh_margin_s, now + self.max_ttl_s)
        if expires_at <= now:
            return False
        with self._lock:
            self._entries[key] = (expires_at, value)
            self._entries.move_to_end(key)
            while len(self._entries) > self.max_entries:
                self._entries.popitem(last=False)
        return True

    def __len__(self) -> int:
        return len(self._entries)

    def __repr__(self) -> str:
        return f"TokenCache(entries={len(self)}, max_entries={self.max_entries})"
