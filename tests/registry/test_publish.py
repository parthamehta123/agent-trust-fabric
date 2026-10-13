"""Bundle publisher (ADR-0022 §7): what gets published, when, and what is refused."""

from __future__ import annotations

import datetime as dt
import pathlib
import threading
from typing import Any

import boto3
import pytest
from atf_agent_registry.publish import BundlePublisher, PublishError, to_grant
from atf_agent_registry.records import AgentSpec, ApprovalRole, InMemoryRegistryStore
from atf_agent_registry.store_dynamo import DynamoRegistryStore, ensure_local_table
from moto import mock_aws

from tests.policy.test_bundle import SIGNER
from tests.policy.test_pdp import GUARDRAILS
from tests.registry.test_workflow import AGENT, BOB, CAROL, DAVE, T0, Env, spec
from trustkit_policy.bundle import BundleVerifier
from trustkit_policy.grants import AgentGrant
from trustkit_policy.pdp import DecisionRequest, Resource
from trustkit_policy.schema import Action, ResourceType
from trustkit_policy.sources import FileBundleSink, FileBundleSource

ISS = "atf-bundle-publisher"


class Sink:
    def __init__(self) -> None:
        self.published: list[bytes] = []
        self.fail = False

    def publish(self, data: bytes) -> None:
        if self.fail:
            raise OSError("sink down")
        self.published.append(data)


class Rig:
    def __init__(self, guardrails: str = GUARDRAILS) -> None:
        self.env = Env()
        self.sink = Sink()
        self.pub = BundlePublisher(
            self.env.store,
            SIGNER,
            self.sink,
            guardrails=guardrails,
            issuer=ISS,
            now=self.env.clock,
        )

    def verify_last(self) -> Any:
        now = int(self.env.clock.t.timestamp())
        return BundleVerifier(SIGNER.public_jwk(), issuer=ISS, now=lambda: now).verify(
            self.sink.published[-1]
        )


@pytest.fixture
def rig() -> Rig:
    return Rig()


class TestToGrant:
    def test_every_security_field_carried(self) -> None:
        """Drift guard: adding a spec field without mapping it fails here."""
        mapped = {"display_name", "description"}  # presentation-only, deliberately not carried
        carried = set(AgentSpec.model_fields) - mapped
        grant_fields = set(AgentGrant.model_fields)
        assert carried <= grant_fields, carried - grant_fields

    def test_mapping(self, rig: Rig) -> None:
        v = rig.env.approved(
            spec(
                tier="privileged",
                ingress={
                    "t2_issuer": "https://idp.example/oauth2/a",
                    "t2_audience": "api://a",
                    "t2_jwks_uri": "https://idp.example/oauth2/a/v1/keys",
                },
                delegation={"may_delegate_to": ["0oa-agent-beta"]},
            )
        )
        g = to_grant(v)
        assert g.agent_id == AGENT
        assert g.record_version == v.version
        assert g.tier == "privileged"
        assert g.tools == {"tickets": frozenset({"tickets.read"})}
        assert g.ingress is not None
        assert g.delegation.may_delegate_to == frozenset({"0oa-agent-beta"})
        assert g.expires_at == int((T0 + dt.timedelta(days=90)).timestamp())


class TestBuild:
    def test_only_effective_records(self, rig: Rig) -> None:
        e = rig.env
        e.approved()  # AGENT approved v1
        e.svc.create_draft(DAVE, AGENT, spec(display_name="v2 draft"))  # open draft ignored
        for agent, state in [("0oa-rejected", "reject"), ("0oa-in-review", None)]:
            v = e.svc.create_draft(DAVE, agent, spec())
            e.svc.submit(DAVE, agent, v.version)
            if state == "reject":
                e.svc.reject(BOB, agent, v.version)
        r = e.svc.create_draft(DAVE, "0oa-revoked", spec())
        e.svc.submit(DAVE, "0oa-revoked", r.version)
        e.svc.approve(BOB, "0oa-revoked", r.version, ApprovalRole.APPROVER)
        e.svc.revoke(CAROL, "0oa-revoked")
        b = rig.pub.build()
        assert set(b.agents) == {AGENT}
        assert b.agents[AGENT].record_version == 1

    def test_expired_privileged_excluded(self, rig: Rig) -> None:
        rig.env.approved(spec(tier="privileged"))
        rig.env.clock.t = T0 + dt.timedelta(days=91)
        assert rig.pub.build().agents == {}

    def test_versions_strictly_increase(self, rig: Rig) -> None:
        a, b = rig.pub.build(), rig.pub.build()
        assert b.bundle_version > a.bundle_version

    def test_policies_are_permits_plus_guardrails(self, rig: Rig) -> None:
        rig.env.approved()
        b = rig.pub.build()
        assert '@id("grant:0oa-agent-alpha:tool:tickets")' in b.policies
        assert '@id("guardrail:user-scopes")' in b.policies
        assert b.exp - b.iat == 600

    @pytest.mark.security
    def test_invalid_guardrails_refuse_to_publish(self) -> None:
        r = Rig(guardrails="permit(")
        r.env.approved()
        with pytest.raises(PublishError):
            r.pub.publish()
        assert r.sink.published == []


class TestPublish:
    def test_published_bundle_verifies_and_decides(self, rig: Rig) -> None:
        rig.env.approved()
        version = rig.pub.publish()
        b = rig.verify_last()
        assert b.bundle_version == version
        from trustkit_policy.pdp import CedarPdp

        pdp = CedarPdp(b.policies, b.agents)
        d = pdp.decide(
            DecisionRequest(
                agent_id=AGENT,
                action=Action.INVOKE_TOOL,
                resource=Resource(ResourceType.MCP_SERVER, "tickets", {"delegation": "token"}),
                context={"user": "u", "scopes": ["tickets.read"], "user_scopes": ["tickets.read"]},
            )
        )
        assert d.allowed

    @pytest.mark.security
    def test_sink_failure_is_publish_error(self, rig: Rig) -> None:
        rig.sink.fail = True
        with pytest.raises(PublishError):
            rig.pub.publish()

    def test_file_sink_end_to_end(self, rig: Rig, tmp_path: pathlib.Path) -> None:
        rig.env.approved()
        pub = BundlePublisher(
            rig.env.store,
            SIGNER,
            FileBundleSink(tmp_path),
            guardrails=GUARDRAILS,
            issuer=ISS,
            now=rig.env.clock,
        )
        pub.publish()
        raw = FileBundleSource(tmp_path / "bundle.jws").fetch()
        assert raw is not None
        now = int(rig.env.clock.t.timestamp())
        assert (
            AGENT
            in BundleVerifier(SIGNER.public_jwk(), issuer=ISS, now=lambda: now).verify(raw).agents
        )


class TestTick:
    def test_first_tick_publishes(self, rig: Rig) -> None:
        assert rig.pub.tick() is not None
        assert rig.pub.tick() is None  # nothing changed, heartbeat not due

    def test_publishes_on_change(self, rig: Rig) -> None:
        rig.pub.tick()
        rig.env.approved()
        assert rig.pub.tick() is not None
        assert AGENT in rig.verify_last().agents

    @pytest.mark.security
    def test_revocation_publishes_immediately(self, rig: Rig) -> None:
        rig.env.approved()
        rig.pub.tick()
        rig.env.svc.revoke(CAROL, AGENT)
        assert rig.pub.tick() is not None
        assert rig.verify_last().agents == {}

    def test_heartbeat(self, rig: Rig) -> None:
        rig.pub.tick()
        rig.env.clock.t += dt.timedelta(seconds=299)
        assert rig.pub.tick() is None
        rig.env.clock.t += dt.timedelta(seconds=1)
        assert rig.pub.tick() is not None

    def test_expiry_counts_as_change(self, rig: Rig) -> None:
        rig.env.approved(spec(tier="privileged"))
        rig.pub.tick()
        rig.env.clock.t = T0 + dt.timedelta(days=90)
        assert rig.pub.tick() is not None
        assert rig.verify_last().agents == {}

    def test_failed_publish_retried_next_tick(self, rig: Rig) -> None:
        rig.sink.fail = True
        assert rig.pub.tick() is None
        rig.sink.fail = False
        assert rig.pub.tick() is not None

    def test_run_forever_stops(self, rig: Rig) -> None:
        stop = threading.Event()
        t = threading.Thread(target=rig.pub.run_forever, args=(stop, 0.01))
        t.start()
        while not rig.sink.published:
            pass
        stop.set()
        t.join(timeout=5)
        assert not t.is_alive()


class TestCounter:
    def test_memory_counter(self) -> None:
        s = InMemoryRegistryStore()
        assert [s.next_bundle_version() for _ in range(3)] == [1, 2, 3]

    def test_dynamo_counter_survives_new_store_and_is_hidden(self) -> None:
        with mock_aws():
            c = boto3.client("dynamodb", region_name="us-east-1")
            ensure_local_table(c, "agents")
            s1 = DynamoRegistryStore(c, "agents")
            assert [s1.next_bundle_version() for _ in range(2)] == [1, 2]
            assert DynamoRegistryStore(c, "agents").next_bundle_version() == 3  # restart
            assert s1.agent_ids() == []  # reserved item never looks like an agent

    def test_concurrent_counter_unique(self) -> None:
        with mock_aws():
            c = boto3.client("dynamodb", region_name="us-east-1")
            ensure_local_table(c, "agents")
            s = DynamoRegistryStore(c, "agents")
            got: list[int] = []
            lock = threading.Lock()

            def take() -> None:
                for _ in range(10):
                    v = s.next_bundle_version()
                    with lock:
                        got.append(v)

            threads = [threading.Thread(target=take) for _ in range(5)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            assert sorted(got) == list(range(1, 51))


@pytest.mark.security
class TestStoreDown:
    class Down(InMemoryRegistryStore):
        def agent_ids(self) -> Any:
            from atf_agent_registry.records import StoreUnavailableError

            raise StoreUnavailableError

    def test_build_and_tick_fail_closed(self) -> None:
        r = Rig()
        r.pub = BundlePublisher(
            self.Down(), SIGNER, r.sink, guardrails=GUARDRAILS, issuer=ISS, now=r.env.clock
        )
        with pytest.raises(PublishError):
            r.pub.build()
        assert r.pub.tick() is None
        assert r.sink.published == []
