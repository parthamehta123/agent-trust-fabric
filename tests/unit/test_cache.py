"""TokenCache and cache_key (ADR-0003 as amended by ADR-0011)."""

from __future__ import annotations

import pytest

from trustkit.cache import TokenCache, cache_key

T0 = 1_800_000_000


class Clock:
    def __init__(self) -> None:
        self.t = T0

    def __call__(self) -> int:
        return self.t


BASE_KEY = {"at_jti": "a", "idt_jti": "i", "subject": "s", "audience": "aud", "profile_id": "p"}


@pytest.mark.security
class TestCacheKey:
    @pytest.mark.parametrize("missing", ["at_jti", "idt_jti"])
    @pytest.mark.parametrize("value", [None, ""])
    def test_no_key_without_both_jtis(self, missing: str, value: str | None) -> None:
        """ADR-0011: never fall back to a weaker key."""
        assert cache_key(**{**BASE_KEY, missing: value}) is None

    @pytest.mark.parametrize("field", list(BASE_KEY))
    def test_every_component_changes_key(self, field: str) -> None:
        """TM-EXC-03"""
        assert cache_key(**BASE_KEY) != cache_key(**{**BASE_KEY, field: "different"})

    def test_components_are_unambiguous(self) -> None:
        """TM-EXC-03: ('ab','c') must not collide with ('a','bc'): length-prefix parts."""
        k1 = cache_key(**{**BASE_KEY, "at_jti": "ab", "idt_jti": "c"})
        k2 = cache_key(**{**BASE_KEY, "at_jti": "a", "idt_jti": "bc"})
        assert k1 != k2

    def test_key_is_a_digest(self) -> None:
        """Keys may appear in debug output; they must not reveal subjects or jtis."""
        k = cache_key(**{**BASE_KEY, "subject": "00u-alice"})
        assert k is not None
        assert "00u-alice" not in k
        assert len(k) == 64


class TestTokenCache:
    def test_put_get(self) -> None:
        c: TokenCache[str] = TokenCache(now=Clock())
        assert c.put("k", "v", exp=T0 + 300)
        assert c.get("k") == "v"

    def test_ttl_is_exp_minus_margin(self) -> None:
        clock = Clock()
        c: TokenCache[str] = TokenCache(now=clock, refresh_margin_s=30)
        c.put("k", "v", exp=T0 + 100)
        clock.t = T0 + 69
        assert c.get("k") == "v"
        clock.t = T0 + 70
        assert c.get("k") is None

    def test_ttl_capped_by_max(self) -> None:
        clock = Clock()
        c: TokenCache[str] = TokenCache(now=clock, max_ttl_s=300)
        c.put("k", "v", exp=T0 + 3600)
        clock.t = T0 + 301
        assert c.get("k") is None

    def test_not_stored_inside_margin(self) -> None:
        c: TokenCache[str] = TokenCache(now=Clock(), refresh_margin_s=30)
        assert not c.put("k", "v", exp=T0 + 30)
        assert c.get("k") is None

    @pytest.mark.security
    def test_bounded_lru(self) -> None:
        """TM-EXC-03 / TM-ING-05: a flood of sessions can't grow memory without bound."""
        c: TokenCache[int] = TokenCache(now=Clock(), max_entries=3)
        for i in range(10):
            c.put(f"k{i}", i, exp=T0 + 300)
        assert len(c) == 3
        assert c.get("k0") is None
        assert c.get("k9") == 9

    def test_get_refreshes_recency(self) -> None:
        c: TokenCache[int] = TokenCache(now=Clock(), max_entries=2)
        c.put("a", 1, exp=T0 + 300)
        c.put("b", 2, exp=T0 + 300)
        c.get("a")
        c.put("c", 3, exp=T0 + 300)
        assert c.get("a") == 1
        assert c.get("b") is None

    def test_repr_has_no_values(self) -> None:
        c: TokenCache[str] = TokenCache(now=Clock())
        c.put("k", "SECRET-TOKEN", exp=T0 + 300)
        assert "SECRET" not in repr(c)

    @pytest.mark.parametrize(
        "bad", [{"max_entries": 0}, {"max_ttl_s": 0}, {"refresh_margin_s": -1}]
    )
    def test_rejects_invalid_config(self, bad: dict[str, int]) -> None:
        with pytest.raises(ValueError):  # noqa: PT011 - any ValueError is fine for bad config
            TokenCache(now=Clock(), **bad)  # type: ignore[arg-type]
