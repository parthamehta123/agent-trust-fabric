"""Audit event schema (TM-ING-07, TM-AUD-02)."""

from __future__ import annotations

import io
import json

import pytest

from trustkit.audit import AuditEvent, Decision, JsonLinesSink, jti_hash

JWT = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJlLWJ5dGVz"


def event(**kw: object) -> AuditEvent:
    base: dict[str, object] = {
        "event_type": "interceptor.request",
        "request_id": "req-1",
        "decision": Decision.ALLOW,
        "reason": "ok",
    }
    base.update(kw)
    return AuditEvent(**base)  # type: ignore[arg-type]


class TestAuditEvent:
    def test_json_is_one_line_stable_and_omits_none(self) -> None:
        line = event(subject="00u-alice", scan_categories=("pii",)).to_json()
        assert "\n" not in line
        d = json.loads(line)
        assert d == {
            "event_type": "interceptor.request",
            "request_id": "req-1",
            "decision": "allow",
            "reason": "ok",
            "subject": "00u-alice",
            "scan_categories": ["pii"],
            "scanner_failed_open": False,
        }
        assert list(d) == sorted(d)

    def test_jti_hash(self) -> None:
        assert jti_hash(None) is None
        h = jti_hash("abc")
        assert h is not None
        assert len(h) == 64
        assert "abc" not in h

    @pytest.mark.security
    @pytest.mark.parametrize(
        "field", ["reason", "subject", "client_id", "request_id", "gateway_id", "t2_jti_sha256"]
    )
    def test_token_shaped_values_rejected(self, field: str) -> None:
        """TM-AUD-02: the audit log must never become a token store, even by accident."""
        with pytest.raises(ValueError, match="token"):
            event(**{field: f"prefix {JWT} suffix"})

    @pytest.mark.security
    def test_token_in_categories_rejected(self) -> None:
        with pytest.raises(ValueError, match="token"):
            event(scan_categories=("pii", JWT))

    def test_no_free_form_fields(self) -> None:
        """Closed schema: unknown fields can't be attached."""
        with pytest.raises(TypeError):
            event(extra={"anything": 1})


class TestSink:
    def test_writes_lines(self) -> None:
        buf = io.StringIO()
        sink = JsonLinesSink(buf)
        sink.emit(event())
        sink.emit(event(decision=Decision.DENY, reason="binding_failed"))
        lines = buf.getvalue().splitlines()
        assert [json.loads(x)["decision"] for x in lines] == ["allow", "deny"]
