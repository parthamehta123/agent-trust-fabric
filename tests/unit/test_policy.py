"""Target header allowlist policy (ADR-0014 §5)."""

from __future__ import annotations

import pytest

from trustkit.policy import RESERVED_HEADERS, AllowlistViolationError, check_target_allowlist

OK = sorted(RESERVED_HEADERS)


class TestAllowlist:
    def test_reserved_only_is_ok(self) -> None:
        check_target_allowlist(OK)

    def test_extra_non_credential_header_ok(self) -> None:
        check_target_allowlist([*OK, "x-correlation-id"])

    @pytest.mark.security
    @pytest.mark.parametrize(
        "bad", ["Authorization", "X-Subject-Token", "cookie", "Proxy-Authorization", "x-api-key"]
    )
    def test_credential_headers_rejected(self, bad: str) -> None:
        """TM-ING-06: caller credentials must never be propagated to a target."""
        with pytest.raises(AllowlistViolationError, match=bad.lower()):
            check_target_allowlist([*OK, bad])

    @pytest.mark.security
    @pytest.mark.parametrize("missing", sorted(RESERVED_HEADERS))
    def test_every_reserved_header_required(self, missing: str) -> None:
        """ADR-0012 §4: an overwrite that can't reach the target isn't an overwrite."""
        with pytest.raises(AllowlistViolationError, match=missing):
            check_target_allowlist([h for h in OK if h != missing])

    @pytest.mark.security
    def test_case_insensitive_duplicates_rejected(self) -> None:
        with pytest.raises(AllowlistViolationError):
            check_target_allowlist([*OK, "X-ATF-DECISION"])
