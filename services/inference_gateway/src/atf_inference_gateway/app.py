"""HTTP shell: ``POST /v1/chat/completions`` (OpenAI-compatible subset) and ``GET /ping``.

Auth: ``Authorization: Bearer <workload token>`` validated by ``workload_validator``; the agent is
the token's ``client_id`` (== ``sub``). Duplicate header names are rejected. Errors are
``{"error": {"type": <code>}}`` with the ``ChatError`` status; nothing provider-specific leaks.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from atf_inference_gateway.service import ChatError, InferenceService
from trustkit.jwt import TokenValidationError, TokenValidator


def _err(status: int, code: str) -> JSONResponse:
    headers = {"WWW-Authenticate": "Bearer"} if status == 401 else None
    return JSONResponse({"error": {"type": code}}, status_code=status, headers=headers)


def create_app(service: InferenceService, workload_validator: TokenValidator) -> FastAPI:
    app = FastAPI(title="inference-gateway", docs_url=None, redoc_url=None)

    @app.post("/v1/chat/completions")
    async def completions(request: Request) -> Response:
        names = [n.decode("latin-1").lower() for n, _ in request.headers.raw]
        if len(names) != len(set(names)):
            return _err(400, "invalid_request")  # header smuggling
        auth = request.headers.get("authorization", "")
        if not auth.startswith("Bearer "):
            return _err(401, "unauthorized")
        try:
            token = workload_validator.validate(auth.removeprefix("Bearer "))
        except TokenValidationError:
            return _err(401, "unauthorized")
        agent = token.claims.get("client_id")
        if not isinstance(agent, str) or token.claims.get("sub") != agent:
            return _err(401, "unauthorized")  # a workload token names the agent as sub == client_id
        try:
            body = json.loads(await request.body())
        except (ValueError, RecursionError):
            return _err(400, "invalid_request")
        try:
            result = await run_in_threadpool(service.chat, agent, body)
        except ChatError as e:
            return _err(e.status, e.code)
        return JSONResponse(result)

    @app.get("/ping")
    def ping() -> dict[str, str]:
        return {"status": "ok"}

    return app


def build_app(env: Mapping[str, str]) -> FastAPI:
    """Env-driven wiring. Required variables are read up front: a missing one fails cold start.

    ``ATF_INFERENCE_PROFILE_PATH``, ``ATF_MODEL_ROUTES_PATH``, ``ATF_BUDGET_TABLE``,
    ``ATF_CA_BUNDLE``; optional ``ATF_GUARDRAIL_ID``/``ATF_GUARDRAIL_VERSION`` (else local rules),
    ``AWS_REGION``. With ``ATF_ENV=local`` the budget table is created if missing.
    """
    import datetime
    import pathlib
    import sys

    import boto3

    from atf_inference_gateway.budget import DynamoBudgetStore
    from atf_inference_gateway.llm import configure_tls, litellm_complete
    from atf_inference_gateway.policy import load_inference_profile
    from atf_inference_gateway.routes import load_routes, routed
    from trustkit.audit import JsonLinesSink
    from trustkit.jwt import JwksKeyResolver, ValidationPolicy
    from trustkit.scanning import ContentScanner, LocalRulesScanner
    from trustkit_aws.s3_bundles import s3_source_factory
    from trustkit_http.endpoint import HttpxTokenEndpoint
    from trustkit_policy.runtime import policy_from_env

    profile_path, routes_path = env["ATF_INFERENCE_PROFILE_PATH"], env["ATF_MODEL_ROUTES_PATH"]
    table, ca = env["ATF_BUDGET_TABLE"], env["ATF_CA_BUNDLE"]
    region = env.get("AWS_REGION", "us-east-1")

    profile = load_inference_profile(pathlib.Path(profile_path).read_bytes())
    routes = load_routes(pathlib.Path(routes_path).read_bytes(), env=env)
    configure_tls(ca)

    http = HttpxTokenEndpoint(ca_bundle_path=ca)
    jwks_uri = profile.inbound.jwks_uri
    validator = TokenValidator(
        ValidationPolicy(
            issuer=profile.inbound.issuer,
            audiences=frozenset(profile.inbound.audiences),
            expected_typ="at+jwt",
        ),
        JwksKeyResolver(fetch=lambda: http.get_json(jwks_uri)),
    )

    ddb = boto3.client("dynamodb", region_name=region)
    if env.get("ATF_ENV") == "local":
        _ensure_local_table(ddb, table)

    scanner: ContentScanner
    if env.get("ATF_GUARDRAIL_ID"):
        from trustkit_aws.guardrails import BedrockGuardrailScanner

        scanner = BedrockGuardrailScanner(
            boto3.client("bedrock-runtime", region_name=region),
            guardrail_id=env["ATF_GUARDRAIL_ID"],
            version=env["ATF_GUARDRAIL_VERSION"],
        )
    else:
        scanner = LocalRulesScanner()

    service = InferenceService(
        profile=profile,
        budget=DynamoBudgetStore(ddb, table),
        scanner=scanner,
        complete=routed(routes, litellm_complete),
        today=lambda: datetime.datetime.now(datetime.UTC).date().isoformat(),
        policy=policy_from_env(
            env, s3_factory=s3_source_factory(region), audit=JsonLinesSink(sys.stdout)
        ),
        routable=frozenset(routes),
    )
    return create_app(service, validator)


def _ensure_local_table(ddb: Any, table: str) -> None:
    """Local stack only (DynamoDB Local): create the table if missing. Phase 6 Terraform owns it."""
    try:
        ddb.describe_table(TableName=table)
    except ddb.exceptions.ResourceNotFoundException:
        ddb.create_table(
            TableName=table,
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
            AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
            BillingMode="PAY_PER_REQUEST",
        )
        ddb.get_waiter("table_exists").wait(TableName=table)


def app_from_env() -> FastAPI:
    import os

    return build_app(dict(os.environ))
