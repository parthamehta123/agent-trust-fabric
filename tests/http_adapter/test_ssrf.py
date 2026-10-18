"""SSRF guard (ADR-0017 §4, TM-TOOL-06)."""

from __future__ import annotations

import ipaddress
import json

import httpx
import pytest

from trustkit_http.ssrf import (
    InternalHosts,
    PinnedClient,
    SsrfConfigError,
    SsrfError,
    is_forbidden_ip,
    parse_internal_hosts,
    vet_url,
)

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


# ----------------------------------------------------------------------------- internal hosts


KB = "knowledge.atf.example.com"
SUBNETS = ["10.40.0.0/20", "10.40.16.0/20"]


def internal(doc: object) -> dict[str, str]:
    return {"ATF_ENV": "dev", "ATF_SSRF_INTERNAL_HOSTS": json.dumps(doc)}


@pytest.mark.security
class TestInternalHosts:
    """Named internal hosts (ADR-0026 §19): private targets by exact name, confined addresses."""

    def hosts(self) -> InternalHosts:
        return parse_internal_hosts(internal({KB: SUBNETS}))

    def test_parse_allowed_outside_local(self) -> None:
        h = self.hosts()
        assert set(h) == {KB}
        assert h[KB] == frozenset(ipaddress.ip_network(c) for c in SUBNETS)

    def test_unset_or_empty(self) -> None:
        assert parse_internal_hosts({}) == {}
        assert parse_internal_hosts({"ATF_SSRF_INTERNAL_HOSTS": "  "}) == {}

    def test_named_host_reaches_its_subnet(self) -> None:
        t = vet_url(
            f"https://{KB}/mcp", resolver=resolver("10.40.3.9"), internal_hosts=self.hosts()
        )
        assert (t.hostname, t.ip) == (KB, "10.40.3.9")

    def test_trailing_dot_is_the_same_host(self) -> None:
        vet_url(f"https://{KB}./mcp", resolver=resolver("10.40.3.9"), internal_hosts=self.hosts())

    @pytest.mark.parametrize(
        "ips",
        [
            ["10.41.0.1"],  # another private range
            ["10.40.3.9", "10.99.0.1"],  # one answer outside poisons the set
            ["10.40.3.9", PUBLIC],  # even a public answer: the host is confined
            ["169.254.169.254"],
            ["127.0.0.1"],
            ["::ffff:10.40.3.9"],  # mapped forms never match an IPv4 network
        ],
    )
    def test_named_host_confined(self, ips: list[str]) -> None:
        with pytest.raises(SsrfError, match="outside its allowed networks"):
            vet_url(f"https://{KB}/mcp", resolver=resolver(*ips), internal_hosts=self.hosts())

    @pytest.mark.parametrize(
        "host",
        [
            "registry.atf.example.com",  # a sibling name: no suffix matching
            "x.knowledge.atf.example.com",  # a subdomain: no wildcard
            "knowledge.atf.example.com.evil.test",
        ],
    )
    def test_other_names_stay_public_only(self, host: str) -> None:
        with pytest.raises(SsrfError, match="non-public"):
            vet_url(
                f"https://{host}/mcp", resolver=resolver("10.40.3.9"), internal_hosts=self.hosts()
            )

    def test_public_hosts_unaffected(self) -> None:
        vet_url(
            "https://tools.example.com/mcp", resolver=resolver(PUBLIC), internal_hosts=self.hosts()
        )

    @pytest.mark.parametrize(
        "doc",
        [
            [KB],
            {KB: []},
            {KB: "10.40.0.0/20"},
            {KB: [17]},
            {"Knowledge.atf.example.com": SUBNETS},  # must be lowercase
            {"knowledge": SUBNETS},  # single label
            {"*.atf.example.com": SUBNETS},  # no wildcards
            {"10.40.0.5": SUBNETS},  # all-numeric labels are not a host name
            {KB: ["169.254.0.0/16"]},  # link-local / metadata
            {KB: ["127.0.0.0/8"]},
            {KB: ["100.64.0.0/16"]},  # CGNAT
            {KB: ["10.0.0.0/8"]},  # too wide
            {KB: ["0.0.0.0/0"]},
            {KB: ["10.40.0.1/20"]},  # host bits set
            {f"h{i}.example.com": SUBNETS for i in range(65)},  # too many
        ],
    )
    def test_bad_config_refused(self, doc: object) -> None:
        with pytest.raises(SsrfConfigError):
            parse_internal_hosts(internal(doc))

    def test_not_json_refused(self) -> None:
        with pytest.raises(SsrfConfigError):
            parse_internal_hosts({"ATF_SSRF_INTERNAL_HOSTS": "knowledge=10.40.0.0/20"})

    def test_pinned_client_honours_internal_hosts(self) -> None:
        seen: list[str] = []

        def handler(req: httpx.Request) -> httpx.Response:
            seen.append(str(req.url.host))
            return httpx.Response(200, json={"ok": True})

        c = PinnedClient(
            resolver=resolver("10.40.3.9"),
            transport=httpx.MockTransport(handler),
            internal_hosts=self.hosts(),
        )
        assert c.post_json(f"https://{KB}/mcp", {}, headers={}) == (200, {"ok": True})
        assert seen == ["10.40.3.9"]
        with pytest.raises(SsrfError):
            c.post_json("https://registry.atf.example.com/x", {}, headers={})


@pytest.mark.security
class TestUrlShape:
    """``check_url_shape`` is the DNS-free half of ``vet_url``, shared with the registry."""

    def test_shape_fields(self) -> None:
        from trustkit_http.ssrf import check_url_shape

        s = check_url_shape("https://Agent.Example.com:8443/a2a?x=1")
        assert (s.hostname, s.port, s.path) == ("agent.example.com", 8443, "/a2a?x=1")

    @pytest.mark.parametrize(
        "url",
        ["http://a.example.com/", "https://a/", "https://1.2.3.4/", "https://u@a.example.com/"],
    )
    def test_vet_url_and_shape_agree(self, url: str) -> None:
        from trustkit_http.ssrf import check_url_shape

        with pytest.raises(SsrfError):
            check_url_shape(url)
        with pytest.raises(SsrfError):
            vet_url(url, resolver=resolver(PUBLIC))
