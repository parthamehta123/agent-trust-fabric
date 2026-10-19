"""Opt-in probes against a real Okta tenant (docs/runbooks/okta-preflight.md). They verify A-2,
A-12, A-14, A-15 and A-16 before any AWS spend.

Nothing here runs unless **both** are set, so CI and a laptop never call Okta by accident:

* ``ATF_OKTA_PROBES=1``
* ``ATF_OKTA_CONFIG``: path to the tenant config (``.okta-preflight/config.json``)

Probes that need a signed-in user also need ``ATF_OKTA_LOGIN=1``: your browser opens and you sign
in yourself. A probe that Okta *refuses* **fails** (the assumption is refuted); a skip only ever
means the probe didn't run. ``build/okta-preflight.md`` summarises the run without token material.
"""

from __future__ import annotations

import os
import pathlib
from collections.abc import Callable, Iterator, Mapping
from typing import Any

import pytest

from tests.okta_probes.config import OktaPreflightConfig, load_config
from tests.okta_probes.report import Report, safe
from trustkit.jwt import JwksKeyResolver, KeyResolver
from trustkit.signing import InMemoryEs256Signer, KeySigner
from trustkit_http.endpoint import HttpxTokenEndpoint

ROOT = pathlib.Path(__file__).parents[2]
KEYS_DIR = ROOT / ".okta-preflight" / "keys"
REPORT_PATH = ROOT / "build" / "okta-preflight.md"


def probes_enabled(env: Mapping[str, str]) -> bool:
    return (
        env.get("ATF_OKTA_PROBES") == "1"
        and pathlib.Path(env.get("ATF_OKTA_CONFIG", "/nonexistent")).is_file()
    )


ENABLED = probes_enabled(os.environ)
REASON = "Okta probes are opt-in: ATF_OKTA_PROBES=1 and ATF_OKTA_CONFIG"
_REPORT = Report()
_EVIDENCE: dict[str, dict[str, str]] = {}


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    here = pathlib.Path(__file__).parent
    for item in items:
        if here in pathlib.Path(str(item.fspath)).parents:
            item.add_marker(pytest.mark.okta)
            if not ENABLED:
                item.add_marker(pytest.mark.skip(reason=REASON))


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item: pytest.Item, call: pytest.CallInfo[None]) -> Iterator[None]:
    outcome = yield
    rep = outcome.get_result()  # type: ignore[attr-defined]
    marker = item.get_closest_marker("assumption")
    if marker is None or not ENABLED or rep.when not in ("setup", "call"):
        return
    if rep.when == "setup" and rep.passed:
        return  # the call phase reports
    if rep.skipped:
        reason = rep.longrepr[2] if isinstance(rep.longrepr, tuple) else "skipped"
        result = f"skipped ({str(reason).removeprefix('Skipped: ')[:120]})"
    elif rep.failed:
        msg = str(call.excinfo.value).splitlines()[0][:120] if call.excinfo else "failed"
        try:
            result = f"**fail**: {safe(msg)}"
        except ValueError:
            result = "**fail** (details withheld: token-shaped)"
    else:
        result = "pass"
    _REPORT.add(marker.args[0], item.name, result, _EVIDENCE.pop(item.nodeid, {}))


def pytest_sessionfinish(session: pytest.Session, exitstatus: int) -> None:
    if ENABLED and _REPORT.rows:
        _REPORT.write(REPORT_PATH)


@pytest.fixture
def evidence(request: pytest.FixtureRequest) -> Callable[[str, Any], None]:
    """``evidence(name, value)``: shapes, booleans and error codes only (checked by ``safe``)."""
    store = _EVIDENCE.setdefault(request.node.nodeid, {})

    def record(name: str, value: Any) -> None:
        store[name] = safe(value)

    return record


@pytest.fixture(scope="session")
def cfg() -> OktaPreflightConfig:
    return load_config(pathlib.Path(os.environ["ATF_OKTA_CONFIG"]))


@pytest.fixture(scope="session")
def http() -> HttpxTokenEndpoint:
    """System trust store, TLS always verified, no redirects (trustkit_http)."""
    return HttpxTokenEndpoint()


@pytest.fixture(scope="session")
def signer() -> Callable[[str], KeySigner]:
    """``signer("chat" | "agent" | "tool-gateway")`` over the keys ``make okta-probe-keys`` made."""
    cache: dict[str, KeySigner] = {}

    def get(name: str) -> KeySigner:
        if name not in cache:
            path = KEYS_DIR / f"{name}.pem"
            if not path.is_file():
                pytest.skip(f"no key for {name}: run `make okta-probe-keys` (runbook step 1)")
            cache[name] = InMemoryEs256Signer(path.read_bytes())
        return cache[name]

    return get


@pytest.fixture(scope="session")
def jwks(http: HttpxTokenEndpoint) -> Callable[[str], KeyResolver]:
    resolvers: dict[str, KeyResolver] = {}

    def get(uri: str) -> KeyResolver:
        if uri not in resolvers:
            resolvers[uri] = JwksKeyResolver(fetch=lambda: http.get_json(uri))
        return resolvers[uri]

    return get


@pytest.fixture(scope="session")
def user(cfg: OktaPreflightConfig, http: HttpxTokenEndpoint, signer: Any) -> Any:
    """One interactive sign-in per run, only with ``ATF_OKTA_LOGIN=1``."""
    if os.environ.get("ATF_OKTA_LOGIN") != "1":
        pytest.skip("needs a signed-in user: ATF_OKTA_LOGIN=1 (your browser opens)")
    from tests.okta_probes.login import login

    return login(cfg, http=http, signer=signer("chat"))
