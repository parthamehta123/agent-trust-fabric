"""SSRF-safe egress to enrolled MCP servers (ADR-0017 §4, TM-TOOL-06).

``vet_url`` accepts only ``https://<dns-name>[:port]/<path>`` (no userinfo, fragment or IP
literal). It resolves the name and rejects it if **any** resolved address is non-public: private,
loopback, link-local (incl. 169.254.169.254), CGNAT 100.64/10, multicast, reserved, unspecified,
benchmarking, documentation, or IPv4-mapped/NAT64 forms of those. One bad answer poisons the set,
so a resolver can't mix in an internal address.

Internal targets in a real deployment (a tool server behind the internal tools ALB, an agent
runtime) are reachable only as **named internal hosts** (ADR-0026 §19,
``ATF_SSRF_INTERNAL_HOSTS``). The hostname must match an entry exactly, and **every** resolved
address must sit inside that entry's private CIDRs. Nothing else about the private range opens up.

``PinnedClient`` re-vets on **every call** and connects to the vetted IP, with ``Host`` and SNI set
to the hostname. The certificate is checked against the hostname, so a DNS rebind between check
and connect can't redirect the request. Redirects are never followed and bodies are size-capped.
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any, Final
from urllib.parse import urlsplit

import httpx

from trustkit_http.endpoint import tls_context

Resolver = Callable[[str, int], list[str]]
"""(hostname, port) -> IP address strings."""

DEFAULT_MAX_RESPONSE_BYTES: Final = 1_048_576
_NAT64: Final = ipaddress.ip_network("64:ff9b::/96")
_SIXTOFOUR: Final = ipaddress.ip_network("2002::/16")
_RFC1918: Final = tuple(
    ipaddress.IPv4Network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
_ULA: Final = ipaddress.IPv6Network("fc00::/7")
_LABEL: Final = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")


Network = ipaddress.IPv4Network | ipaddress.IPv6Network
InternalHosts = Mapping[str, frozenset[Network]]
"""Exact FQDN -> the private networks all of its addresses must fall in."""

MAX_INTERNAL_HOSTS: Final = 64


class SsrfConfigError(ValueError):
    """Unsafe or out-of-place SSRF allowlist configuration (cold-start failure)."""


def parse_local_allowlist(env: Mapping[str, str]) -> frozenset[Network]:
    """``ATF_SSRF_ALLOW_CIDRS`` -> networks (ADR-0018 §1).

    Empty or unset gives an empty set. Set while ``ATF_ENV != "local"`` raises. Each CIDR must be
    RFC 1918 or ULA, have a prefix of at least /16 (v4) or /48 (v6), and not overlap link-local.
    """
    raw = env.get("ATF_SSRF_ALLOW_CIDRS", "").strip()
    if not raw:
        return frozenset()
    if env.get("ATF_ENV") != "local":
        raise SsrfConfigError("an SSRF allowlist is only permitted with ATF_ENV=local")
    return frozenset(_private_net(part) for part in raw.split(","))


def _private_net(raw: object) -> Network:
    """A narrow RFC 1918 (>= /16) or ULA (>= /48) network. Loopback, link-local (including the
    metadata address), CGNAT and public space can never qualify."""
    if not isinstance(raw, str):
        raise SsrfConfigError("invalid CIDR in SSRF allowlist")
    try:
        net = ipaddress.ip_network(raw.strip(), strict=True)
    except ValueError:
        raise SsrfConfigError("invalid CIDR in SSRF allowlist") from None
    if isinstance(net, ipaddress.IPv4Network):
        ok = net.prefixlen >= 16 and any(net.subnet_of(r) for r in _RFC1918)
    else:
        ok = net.prefixlen >= 48 and net.subnet_of(_ULA)
    if not ok:
        raise SsrfConfigError("SSRF allowlist entries must be narrow private subnets")
    return net


def _is_fqdn(hostname: str) -> bool:
    """At least two DNS labels, and not an IPv4 literal (an all-numeric last label never is a
    real TLD)."""
    labels = hostname.split(".")
    return (
        len(labels) >= 2
        and all(_LABEL.fullmatch(lbl) for lbl in labels)
        and not labels[-1].isdigit()
    )


def parse_internal_hosts(env: Mapping[str, str]) -> InternalHosts:
    """``ATF_SSRF_INTERNAL_HOSTS``: a JSON object of exact lowercase FQDN -> list of private CIDRs
    (ADR-0026 §19). Allowed in any environment, because each entry names one host and confines
    its addresses. Unset or empty gives no internal hosts. Anything malformed raises."""
    raw = env.get("ATF_SSRF_INTERNAL_HOSTS", "").strip()
    if not raw:
        return {}
    try:
        doc = json.loads(raw)
    except ValueError:
        raise SsrfConfigError("internal hosts must be a JSON object") from None
    if not isinstance(doc, dict) or len(doc) > MAX_INTERNAL_HOSTS:
        raise SsrfConfigError("internal hosts must be a JSON object of at most 64 entries")
    out: dict[str, frozenset[Network]] = {}
    for host, cidrs in doc.items():
        if not isinstance(host, str) or host != host.lower() or not _is_fqdn(host):
            raise SsrfConfigError("internal host names must be exact lowercase FQDNs")
        if not isinstance(cidrs, list) or not cidrs:
            raise SsrfConfigError("each internal host needs a non-empty list of CIDRs")
        out[host] = frozenset(_private_net(c) for c in cidrs)
    return out


class SsrfError(ValueError):
    """Log-safe: names the rule broken, never the resolved addresses."""


@dataclass(frozen=True)
class VettedTarget:
    hostname: str
    port: int
    path: str
    ip: str


def default_resolver(hostname: str, port: int) -> list[str]:
    return sorted(
        {str(ai[4][0]) for ai in socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)}
    )


def is_forbidden_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address):
        embedded: ipaddress.IPv4Address | None = ip.ipv4_mapped
        if embedded is None and ip in _NAT64:
            embedded = ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
        if embedded is None and ip in _SIXTOFOUR:
            embedded = ipaddress.IPv4Address((int(ip) >> 80) & 0xFFFFFFFF)
        if embedded is not None and is_forbidden_ip(embedded):
            return True
    return (
        not ip.is_global
        or ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def vet_url(
    url: str,
    *,
    resolver: Resolver = default_resolver,
    allow: frozenset[Network] = frozenset(),
    internal_hosts: InternalHosts | None = None,
) -> VettedTarget:
    if "\\" in url or "#" in url or not url.startswith("https://"):
        raise SsrfError("url must be https without fragments or backslashes")
    parts = urlsplit(url)
    if parts.scheme != "https" or "@" in parts.netloc or not parts.hostname:
        raise SsrfError("url must be https://host/path without userinfo")
    hostname = parts.hostname.lower()
    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        raise SsrfError("ip literals are not allowed; enrol a DNS name")
    if not _is_fqdn(hostname.rstrip(".")):
        raise SsrfError("hostname must be a fully qualified DNS name")
    try:
        explicit = parts.port
        port = 443 if explicit is None else explicit  # not `or`: an explicit :0 must be rejected
    except ValueError:
        raise SsrfError("invalid port") from None
    if not 0 < port < 65536:
        raise SsrfError("invalid port")

    try:
        answers = resolver(hostname, port)
    except Exception:  # noqa: BLE001 - any resolution failure is a refusal
        raise SsrfError("hostname did not resolve") from None
    if not answers:
        raise SsrfError("hostname did not resolve")
    try:
        ips = [ipaddress.ip_address(a) for a in answers]
    except ValueError:
        raise SsrfError("resolver returned an invalid address") from None
    confined = (internal_hosts or {}).get(hostname.rstrip("."))
    if confined is not None:
        # A named internal host: every answer must be inside its networks (public ones too, so a
        # poisoned record can't send this host's traffic anywhere else).
        if not all(any(ip in net for net in confined) for ip in ips):
            raise SsrfError("internal host resolves outside its allowed networks")
    elif any(is_forbidden_ip(ip) and not any(ip in net for net in allow) for ip in ips):
        # One internal answer poisons the set; never say which (log-safe, no recon help).
        raise SsrfError("hostname resolves to a non-public address")
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    return VettedTarget(hostname=hostname, port=port, path=path, ip=str(sorted(ips, key=str)[0]))


class PinnedClient:
    def __init__(
        self,
        *,
        resolver: Resolver = default_resolver,
        ca_bundle_path: str | None = None,
        timeout_s: float = 10.0,
        max_response_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
        transport: httpx.BaseTransport | None = None,
        allow: frozenset[Network] = frozenset(),
        internal_hosts: InternalHosts | None = None,
    ) -> None:
        self._resolver = resolver
        self._allow = allow
        self._internal = dict(internal_hosts or {})
        self._max = max_response_bytes
        self._client = httpx.Client(
            verify=tls_context(ca_bundle_path),
            timeout=timeout_s,
            follow_redirects=False,
            transport=transport,
        )

    def post_json(
        self, url: str, payload: Mapping[str, Any], *, headers: Mapping[str, str]
    ) -> tuple[int, dict[str, Any] | None]:
        """Vet, pin, POST. Returns (status, JSON object or None if unacceptable).

        Raises ``SsrfError`` (vetting) or ``httpx.HTTPError`` (transport)."""
        t = vet_url(  # every call: no rebinding
            url, resolver=self._resolver, allow=self._allow, internal_hosts=self._internal
        )
        host = f"[{t.ip}]" if ":" in t.ip else t.ip
        host_header = t.hostname if t.port == 443 else f"{t.hostname}:{t.port}"
        request = self._client.build_request(
            "POST",
            f"https://{host}:{t.port}{t.path}",
            content=json.dumps(dict(payload)).encode(),
            headers={
                **dict(headers),
                "Host": host_header,
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            # TLS SNI and certificate verification use the hostname, not the pinned IP.
            extensions={"sni_hostname": t.hostname},
        )
        response = self._client.send(request, stream=True)
        try:
            return response.status_code, self._read(response)
        finally:
            response.close()

    def _read(self, resp: httpx.Response) -> dict[str, Any] | None:
        if resp.headers.get("content-type", "").split(";")[0].strip().lower() != "application/json":
            return None
        buf = bytearray()
        for chunk in resp.iter_bytes():
            buf += chunk
            if len(buf) > self._max:
                return None
        try:
            parsed = json.loads(buf)
        except (ValueError, RecursionError):
            return None
        return parsed if isinstance(parsed, dict) else None
