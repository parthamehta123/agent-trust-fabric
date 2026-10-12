"""Ephemeral local CA and configs (ADR-0015 §3)."""

from __future__ import annotations

import datetime as dt
import json
import pathlib
import stat

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID

from devstack.bootstrap import DEFAULT_SERVICES, MAX_VALIDITY_DAYS, BootstrapResult, bootstrap
from mock_idp.app import build_idp_from_topology
from trustkit.profiles import load_profiles

BASE = "https://mock-idp:8443"


@pytest.fixture(scope="module")
def result(tmp_path_factory: pytest.TempPathFactory) -> BootstrapResult:
    return bootstrap(tmp_path_factory.mktemp("ca") / ".local-ca", idp_base_url=BASE)


def cert(path: pathlib.Path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(path.read_bytes())


def mode(path: pathlib.Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


@pytest.mark.security
class TestCa:
    def test_ca_constraints(self, result: BootstrapResult) -> None:
        ca = cert(result.ca_cert)
        bc = ca.extensions.get_extension_for_class(x509.BasicConstraints).value
        assert (bc.ca, bc.path_length) == (True, 0)
        ku = ca.extensions.get_extension_for_class(x509.KeyUsage).value
        assert ku.key_cert_sign
        assert ku.crl_sign
        assert not ku.digital_signature
        assert isinstance(ca.public_key(), ec.EllipticCurvePublicKey)

    def test_short_validity(self, result: BootstrapResult) -> None:
        ca = cert(result.ca_cert)
        assert ca.not_valid_after_utc - ca.not_valid_before_utc <= dt.timedelta(days=7, minutes=5)

    def test_validity_cap_enforced(self, tmp_path: pathlib.Path) -> None:
        with pytest.raises(ValueError, match="validity"):
            bootstrap(tmp_path / "x", validity_days=MAX_VALIDITY_DAYS + 1)

    def test_every_run_is_a_new_ca(self, tmp_path: pathlib.Path) -> None:
        a = cert(bootstrap(tmp_path / "a").ca_cert)
        b = cert(bootstrap(tmp_path / "b").ca_cert)
        assert a.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        ) != b.public_key().public_bytes(
            serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
        )


@pytest.mark.security
class TestLeaves:
    def test_leaf_properties(self, result: BootstrapResult) -> None:
        ca = cert(result.ca_cert)
        for name, (crt_path, _) in result.service_certs.items():
            leaf = cert(crt_path)
            assert leaf.issuer == ca.subject
            leaf.verify_directly_issued_by(ca)
            assert leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
            eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
            assert list(eku) == [ExtendedKeyUsageOID.SERVER_AUTH]
            sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            expected = next(svc.dns_names for svc in DEFAULT_SERVICES if svc.name == name)
            assert sans.get_values_for_type(x509.DNSName) == list(expected)

    def test_runtime_cert_has_no_localhost(self, result: BootstrapResult) -> None:
        """The runtime is never published to the host (ADR-0015 §2), so no localhost SAN."""
        leaf = cert(result.service_certs["agent-runtime"][0])
        sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        assert sans.get_values_for_type(x509.DNSName) == ["agent-runtime"]

    def test_private_key_permissions(self, result: BootstrapResult) -> None:
        assert mode(result.out_dir) == 0o700
        keys = [k for _, k in result.service_certs.values()] + list(result.client_keys.values())
        keys.append(result.out_dir / "ca.key")
        for k in keys:
            assert mode(k) == 0o600, k


class TestConfigs:
    def test_profiles_load_cleanly(self, result: BootstrapResult) -> None:
        reg = load_profiles(result.profiles.read_text())
        assert reg.rejected == {}
        p = reg.lookup("gw-alpha")
        assert p.idp.issuer == BASE
        assert p.ingress_clients == {"0oa-chat": "local:chat"}  # gateway profiles unchanged

    def test_topology_builds_idp_with_matching_client_key(self, result: BootstrapResult) -> None:
        """The mock IdP holds the *public* half of exactly the key the interceptor signs with."""
        topo = json.loads(result.topology.read_text())
        idp = build_idp_from_topology(topo, base_url=BASE)
        assert idp.issuer("agent-alpha") == f"{BASE}/oauth2/agent-alpha"
        priv = serialization.load_pem_private_key(result.client_keys["chat"].read_bytes(), None)
        assert isinstance(priv, ec.EllipticCurvePrivateKey)
        client = next(c for c in topo["clients"] if c["client_id"] == "0oa-chat")
        (jwk,) = client["jwks"]["keys"]
        assert "d" not in jwk
        nums = priv.public_key().public_numbers()
        import base64

        assert base64.urlsafe_b64decode(jwk["x"] + "==") == nums.x.to_bytes(32, "big")

    def test_no_private_material_in_json(self, result: BootstrapResult) -> None:
        for f in (result.topology, result.profiles):
            text = f.read_text()
            assert "PRIVATE KEY" not in text
            assert '"d"' not in text


class TestPhase3Material:
    def test_all_client_keys_and_mcp_egress_profile(self, result: BootstrapResult) -> None:
        assert set(result.client_keys) == {"chat", "agent", "gateway", "admin-alice", "admin-bob"}
        doc = json.loads((result.out_dir / "mcp-egress.json").read_text())
        reg = load_profiles(json.dumps({"version": 1, "profiles": [doc]}))
        assert reg.rejected == {}
        assert "0oa-agent-alpha" in (reg.lookup("mcp-gateway").agents or {})

    def test_topology_has_distinct_admin_clients(self, result: BootstrapResult) -> None:
        topo = json.loads(result.topology.read_text())
        admin = next(s for s in topo["authorization_servers"] if s["as_id"] == "admin")
        assert sorted(admin["clients"]) == ["0oa-admin-alice", "0oa-admin-bob"]
        idp = build_idp_from_topology(topo, base_url=BASE)
        assert idp.issuer("tool-tickets") == f"{BASE}/oauth2/tool-tickets"

    def test_mock_mcp_cert_is_fqdn_only(self, result: BootstrapResult) -> None:
        leaf = cert(result.service_certs["mock-mcp"][0])
        sans = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        assert sans.get_values_for_type(x509.DNSName) == ["mock-mcp.tools.internal"]
