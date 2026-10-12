"""SSRF guard (ADR-0017 §4, TM-TOOL-06)."""

from __future__ import annotations

import ipaddress
import json

import httpx
import pytest
from atf_mcp_gateway.ssrf import PinnedClient, SsrfError, is_forbidden_ip, vet_url

PUBLIC = "93.184.216.34"


def resolver(*ips: str):  # type: ignore[no-untyped-def]
    return lambda host, port: list(ips)


class TestIpClassification:
    @pytest.mark.security
    @pytest.mark.parametrize(
        "ip",
        [
            "10.0.0.1",
            "172.16.0.1",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.169.254",
            "100.64.0.1",
            "0.0.0.0",  # noqa: S104 - an address that must be rejected, not bound
            "224.0.0.1",
            "240.0.0.1",
            "198.18.0.1",
            "192.0.2.1",
            "255.255.255.255",
            "::1",
            "::",
            "fe80::1",
            "fc00::1",
            "ff02::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
            "::ffff:169.254.169.254",
            "64:ff9b::a9fe:a9fe",
        ],
    )
    def test_forbidden(self, ip: str) -> None:
        assert is_forbidden_ip(ipaddress.ip_address(ip))

    @pytest.mark.parametrize("ip", ["8.8.8.8", PUBLIC, "2606:4700:4700::1111"])
    def test_public(self, ip: str) -> None:
        assert not is_forbidden_ip(ipaddress.ip_address(ip))


class TestVetUrl:
    def test_accepts_public_https(self) -> None:
        t = vet_url("https://tools.example.com/mcp", resolver=resolver(PUBLIC))
        assert (t.hostname, t.port, t.path, t.ip) == ("tools.example.com", 443, "/mcp", PUBLIC)

    def test_custom_port_and_query(self) -> None:
        t = vet_url("https://tools.example.com:8443/v1/mcp?x=1", resolver=resolver(PUBLIC))
        assert (t.port, t.path) == (8443, "/v1/mcp?x=1")

    @pytest.mark.security
    @pytest.mark.parametrize(
        "url",
        [
            "http://tools.example.com/mcp",
            "ftp://tools.example.com/",
            "https://user:pw@tools.example.com/mcp",
            "https://tools.example.com/mcp#frag",
            "https://10.0.0.1/mcp",
            "https://[::1]/mcp",
            "https:///mcp",
            "https://tools.example.com:0/mcp",
            "https://tools.example.com:99999/mcp",
            "//tools.example.com/mcp",
            "https://tools.example.com\\@evil.com/",
        ],
    )
    def test_rejects_shape(self, url: str) -> None:
        with pytest.raises(SsrfError):
            vet_url(url, resolver=resolver(PUBLIC))

    @pytest.mark.security
    @pytest.mark.parametrize("ips", [["10.0.0.5"], [PUBLIC, "169.254.169.254"], []])
    def test_rejects_resolution(self, ips: list[str]) -> None:
        """One internal answer poisons the whole set; no answer is a failure."""
        with pytest.raises(SsrfError) as ei:
            vet_url("https://tools.example.com/mcp", resolver=resolver(*ips))
        for ip in ips:
            assert ip not in str(ei.value)

    @pytest.mark.security
    def test_resolver_failure(self) -> None:
        def boom(host: str, port: int) -> list[str]:
            raise OSError("nxdomain")

        with pytest.raises(SsrfError):
            vet_url("https://tools.example.com/mcp", resolver=boom)


@pytest.mark.security
class TestPinnedClient:
    def _client(self, handler, ips: list[list[str]] | None = None):  # type: ignore[no-untyped-def]
        answers = iter(ips or [[PUBLIC]] * 10)
        return PinnedClient(
            resolver=lambda h, p: next(answers),
            transport=httpx.MockTransport(handler),
            max_response_bytes=1024,
        )

    def test_connects_to_vetted_ip_with_hostname_for_host_and_sni(self) -> None:
        seen: list[httpx.Request] = []

        def handler(req: httpx.Request) -> httpx.Response:
            seen.append(req)
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": 1, "result": {}})

        status, body = self._client(handler).post_json(
            "https://tools.example.com/mcp", {"a": 1}, headers={"Authorization": "Bearer t"}
        )
        assert (status, body) == (200, {"jsonrpc": "2.0", "id": 1, "result": {}})
        (req,) = seen
        assert req.url.host == PUBLIC
        assert req.headers["host"] == "tools.example.com"
        assert req.extensions["sni_hostname"] == "tools.example.com"
        assert json.loads(req.content) == {"a": 1}

    def test_dns_rebinding_between_calls(self) -> None:
        client = self._client(lambda r: httpx.Response(200, json={}), ips=[[PUBLIC], ["127.0.0.1"]])
        client.post_json("https://tools.example.com/mcp", {}, headers={})
        with pytest.raises(SsrfError):
            client.post_json("https://tools.example.com/mcp", {}, headers={})

    def test_redirects_not_followed(self) -> None:
        calls: list[str] = []

        def handler(req: httpx.Request) -> httpx.Response:
            calls.append(str(req.url))
            return httpx.Response(
                302, headers={"location": "http://169.254.169.254/latest/meta-data"}
            )

        status, body = self._client(handler).post_json(
            "https://tools.example.com/mcp", {}, headers={}
        )
        assert (status, body, len(calls)) == (302, None, 1)

    @pytest.mark.parametrize(
        "resp",
        [
            httpx.Response(
                200,
                content=b'{"a":"' + b"x" * 5000 + b'"}',
                headers={"content-type": "application/json"},
            ),
            httpx.Response(200, content=b"not json", headers={"content-type": "application/json"}),
            httpx.Response(200, json=[1, 2]),
        ],
    )
    def test_unacceptable_bodies_are_none(self, resp: httpx.Response) -> None:
        assert (
            self._client(lambda r: resp).post_json("https://tools.example.com/mcp", {}, headers={})[
                1
            ]
            is None
        )
