"""IdP-side user entitlements (ADR-0023 §1): restricted scopes are downscoped per user."""

from __future__ import annotations

import base64
import json
from typing import Any

import pytest

from tests.exchange.conftest import ALICE, BOB, World, mint_t2


def scope_of(token: str) -> set[str]:
    seg = token.split(".")[1]
    claims: dict[str, Any] = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
    return set(str(claims["scope"]).split())


@pytest.mark.security
class TestEntitlements:
    def test_entitled_user_gets_the_tool_scope(self, world: World) -> None:
        assert scope_of(mint_t2(world, ALICE)) == {"agent.invoke", "tickets.read"}

    def test_unentitled_user_is_downscoped_not_refused(self, world: World) -> None:
        """RFC 6749 §3.3: the AS may issue fewer scopes than requested."""
        assert scope_of(mint_t2(world, BOB)) == {"agent.invoke"}

    def test_nothing_grantable_is_invalid_scope(self, world: World) -> None:
        with pytest.raises(AssertionError, match="invalid_scope"):
            mint_t2(world, BOB, scope="tickets.read")

    def test_unrestricted_scopes_unaffected(self, world: World) -> None:
        assert scope_of(mint_t2(world, BOB, scope="agent.invoke")) == {"agent.invoke"}
