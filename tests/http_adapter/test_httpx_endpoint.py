"""Hardened httpx adapter (ADR-0011), driven through httpx.MockTransport."""

from __future__ import annotations

import json
from collections.abc import Callable
from typing import Any
from urllib.parse import parse_qs

import httpx
import pytest

from trustkit.exchange import TransportError
from trustkit_http.endpoint import HttpxTokenEndpoint

URL = "https://idp.example.test/oauth2/v1/token"


def endpoint(handler: Callable[[httpx.Request], httpx.Response], **kw: int) -> HttpxTokenEndpoint:
    return HttpxTokenEndpoint(transport=httpx.MockTransport(handler), **kw)  # type: ignore[arg-type]


def json_response(body: object, status: int = 200) -> httpx.Response:
    return httpx.Response(
        status, content=json.dumps(body).encode(), headers={"content-type": "application/json"}
    )


class TestPostForm:
    def test_sends_urlencoded_form_and_parses_json(self) -> None:
        seen: list[httpx.Request] = []

        def handler(req: httpx.Request) -> httpx.Response:
            seen.append(req)
            return json_response({"access_token": "t"})

        r = endpoint(handler).post_form(URL, {"grant_type": "x", "scope": "a b"})
        assert (r.status, dict(r.body)) == (200, {"access_token": "t"})
        (req,) = seen
        assert req.method == "POST"
        assert req.headers["content-type"] == "application/x-www-form-urlencoded"
        assert req.headers["accept"] == "application/json"
        assert parse_qs(req.content.decode()) == {"grant_type": ["x"], "scope": ["a b"]}

    def test_error_status_passed_through(self) -> None:
        r = endpoint(lambda req: json_response({"error": "invalid_grant"}, 400)).post_form(URL, {})
        assert (r.status, r.body["error"]) == (400, "invalid_grant")


@pytest.mark.security
class TestHardening:
    def test_redirect_not_followed(self) -> None:
        """ADR-0011: a 3xx from a token endpoint is a deny, never a hop to Location."""
        calls: list[str] = []

        def handler(req: httpx.Request) -> httpx.Response:
            calls.append(str(req.url))
            return httpx.Response(302, headers={"location": "https://evil.test/steal"})

        r = endpoint(handler).post_form(URL, {"client_assertion": "x"})
        assert r.status == 302
        assert calls == [URL]

    @pytest.mark.parametrize(
        "url", ["http://idp.example.test/token", "ftp://x", "idp.example.test"]
    )
    def test_https_only(self, url: str) -> None:
        with pytest.raises(ValueError, match="https"):
            endpoint(lambda req: json_response({})).post_form(url, {})

    def test_oversized_body_discarded(self) -> None:
        big = json_response({"access_token": "x" * 70_000})
        r = endpoint(lambda req: big, max_response_bytes=65_536).post_form(URL, {})
        assert r.body == {}

    @pytest.mark.parametrize(
        "resp",
        [
            pytest.param(
                httpx.Response(200, content=b'{"a":1}', headers={"content-type": "text/html"}),
                id="wrong-ctype",
            ),
            pytest.param(
                httpx.Response(
                    200, content=b"not json", headers={"content-type": "application/json"}
                ),
                id="bad-json",
            ),
            pytest.param(json_response([1, 2]), id="json-array"),
        ],
    )
    def test_non_object_or_non_json_body_is_empty(self, resp: httpx.Response) -> None:
        assert endpoint(lambda req: resp).post_form(URL, {}).body == {}

    @pytest.mark.parametrize(
        "exc", [httpx.ConnectError("x"), httpx.ConnectTimeout("x"), httpx.ReadTimeout("x")]
    )
    def test_no_response_is_transport_error(self, exc: Exception) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            raise exc

        with pytest.raises(TransportError):
            endpoint(handler).post_form(URL, {})

    def test_transport_error_message_is_log_safe(self) -> None:
        """TM-ING-06: the form (with assertions) must not leak via exception text."""

        def handler(req: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError(f"failed sending {req.content.decode()}")

        with pytest.raises(TransportError) as ei:
            endpoint(handler).post_form(URL, {"client_assertion": "SECRET-ASSERTION"})
        assert "SECRET" not in str(ei.value)
        assert ei.value.__cause__ is None

    def test_tls_verification_cannot_be_disabled(self) -> None:
        """No `verify` parameter exists on the public API."""
        with pytest.raises(TypeError):
            HttpxTokenEndpoint(verify=False)  # type: ignore[call-arg]


class TestGetJson:
    def test_ok(self) -> None:
        assert endpoint(lambda req: json_response({"keys": []})).get_json(URL) == {"keys": []}

    @pytest.mark.parametrize(
        "resp", [json_response({}, 500), httpx.Response(200, content=b"x"), json_response([1])]
    )
    def test_anything_else_raises(self, resp: httpx.Response) -> None:
        """JwksKeyResolver treats a raising fetch as a failed refresh (keeps last-good keys)."""
        with pytest.raises(TransportError):
            endpoint(lambda req: resp).get_json(URL)


@pytest.mark.security
class TestAdapterEdges:
    def test_chunked_body_over_limit_discarded(self) -> None:
        """No Content-Length: the cap must be enforced while streaming, not after."""

        def handler(req: httpx.Request) -> httpx.Response:
            chunks = (b'{"a":"' + b"x" * 1000 + b'"}' for _ in range(1))
            big = (b"x" * 4096 for _ in range(32))
            return httpx.Response(
                200,
                content=iter([next(chunks), *big]),
                headers={"content-type": "application/json"},
            )

        assert endpoint(handler, max_response_bytes=8192).post_form(URL, {}).body == {}

    def test_get_json_transport_error(self) -> None:
        def handler(req: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("x")

        with pytest.raises(TransportError):
            endpoint(handler).get_json(URL)

    def test_invalid_size_limit(self) -> None:
        with pytest.raises(ValueError, match="max_response_bytes"):
            HttpxTokenEndpoint(max_response_bytes=0)

    def test_use_after_close_is_a_programming_error_not_retryable(self) -> None:
        """A closed client is a bug, not a network blip: it must not look like TransportError
        (which the exchanger retries)."""
        ep = endpoint(lambda req: json_response({}))
        ep.close()
        with pytest.raises(RuntimeError, match="closed"):
            ep.post_form(URL, {})


@pytest.mark.security
class TestCaBundle:
    def _ca(self, tmp_path: Any) -> str:
        import datetime as dt

        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID

        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "test-ca")])
        now = dt.datetime.now(dt.UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(name)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(1)
            .not_valid_before(now)
            .not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .sign(key, hashes.SHA256())
        )
        p = tmp_path / "ca.pem"
        p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        return str(p)

    def test_accepts_ca_bundle(self, tmp_path: Any) -> None:
        HttpxTokenEndpoint(ca_bundle_path=self._ca(tmp_path)).close()

    @pytest.mark.parametrize("content", [None, b"not a pem"])
    def test_rejects_missing_or_invalid_bundle(self, tmp_path: Any, content: bytes | None) -> None:
        p = tmp_path / "ca.pem"
        if content is not None:
            p.write_bytes(content)
        with pytest.raises(ValueError, match="ca bundle"):
            HttpxTokenEndpoint(ca_bundle_path=str(p))


class TestJwksMediaType:
    """ADR-0027 review #4: a JWKS may be served as application/jwk-set+json (RFC 7517 §8.5)."""

    def test_jwk_set_media_type_accepted(self) -> None:
        resp = httpx.Response(
            200, content=b'{"keys": []}', headers={"content-type": "application/jwk-set+json"}
        )
        assert endpoint(lambda req: resp).get_json(URL) == {"keys": []}

    def test_token_endpoint_still_json_only(self) -> None:
        resp = httpx.Response(
            200, content=b'{"a": 1}', headers={"content-type": "application/jwk-set+json"}
        )
        assert endpoint(lambda req: resp).post_form(URL, {}).body == {}
