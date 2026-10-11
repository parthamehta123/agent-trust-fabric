# ADR-0012: Interceptor contract, header integrity, and failure semantics

- **Status:** accepted; §5 superseded by [ADR-0013](0013-monotonic-response-path.md)
- **Date:** 2026-10-11
- **Deciders:** Partha Mehta
- **Resolves:** assumption A-1; opens A-5 and A-6
- **Threat-model refs:** TM-ING-04, TM-ING-06, TM-RT-02, TM-INT-01, TM-INT-02, TM-TOOL-04

## Context (verified against AWS documentation, 2026-10-11)

These facts come from the AgentCore Gateway interceptor, configuration and header-propagation
docs (sources are listed at the end):

- **Two payload shapes.**
  - MCP targets use the `mcp` key, with a parsed JSON-RPC body and `rawGatewayRequest`.
  - HTTP targets (AgentCore Runtime, passthrough) and inference targets use the `http` key,
    with **base64** bodies.
  - Both shapes use `interceptorInputVersion` / `interceptorOutputVersion` `"1.0"`.
- **Headers** appear in the input only when `inputConfiguration.passRequestHeaders = true`.
  The default is false.
- **The `Authorization` header** returned by a REQUEST interceptor is forwarded to the target
  and overrides any credential-provider token. Other returned headers are forwarded only if they
  are on the target's `allowedRequestHeaders` allowlist. When the caller and the interceptor both
  set an allowlisted header, the interceptor's value wins.
- **Gateway identity** is available in the Lambda client context as `GATEWAY_ARN`,
  `GATEWAY_ACCOUNT_ID` and `REQUEST_ID` (always present) and `SOURCE_IP` (optional). This is
  documented for HTTP targets.
- **Short-circuit:** returning `transformedGatewayResponse` from a REQUEST interceptor skips the
  target.
  - For **HTTP** targets the RESPONSE interceptor then does **not** run.
  - For **MCP** targets it **still runs**.
- **HTTP RESPONSE events** carry `gatewayRequest: null`.
- **Size limit:** Lambda synchronous invocation is limited to 6 MB of request plus response.
  `payloadFilter.exclude: [RESPONSE_BODY]` removes the response body from the input.
- **Undocumented:** what the gateway does when the interceptor Lambda errors or times out.

## Decisions

1. **One interceptor package, two shape adapters.** The core logic works on a normalised
   request/response model. The `mcp` and `http` adapters translate the shapes in both
   directions. Each adapter is tested against fixtures copied verbatim from the AWS docs (and
   later from captured real events, A-1b).
2. **The profile comes only from `GATEWAY_ARN`** in the client context, resolved to a gateway ID.
   A missing client context, a missing ARN or an unknown gateway means deny. A `Host` header or
   any other caller input is never consulted (TM-ING-04).
3. **The handler never raises (A-6).**
   - The top-level handler catches everything and returns an explicit
     `transformedGatewayResponse`: 401/403 for auth or policy denies, 503 for dependency
     failures.
   - The error body is generic and carries only `REQUEST_ID`.
   - An internal deadline, kept below the Lambda timeout, turns slow dependencies into an
     explicit deny instead of a platform timeout with unknown semantics (TM-INT-01).
4. **Header integrity (A-5).**
   - On every path, including denies, the interceptor output sets **every** header in the
     reserved `x-atf-*` set. "Not applicable" is written as the explicit value `none`.
   - The runtime treats **T2 claims as the source of truth**. `x-atf-*` headers are advisory only
     (scan verdict, correlation ID) and never carry authorization meaning.
   - `X-Subject-Token` and other credential-bearing headers must never appear in any target's
     `allowedRequestHeaders`. Phase 6 Terraform validation will enforce this.
5. **A response after a deny stays denied (TM-INT-02).** The REQUEST interceptor marks its deny
   through a signed or unforgeable channel (design detail in the interceptor checkpoint). The
   RESPONSE handler never upgrades a request-time deny into a pass, and treats an unmarked
   error-shaped response as already handled.
6. **Response scanning is per profile.**
   - Response bodies are scanned by default.
   - `response_body_scan: false` is allowed only for inference profiles, where scanning moves
     into the LiteLLM guardrail (Phase 3). Validation rejects it on ingress profiles.
   - A response too large to scan on a scanning profile follows `scanner_failure_mode`
     (ADR-0004).

## New assumptions to verify on real AWS before Phase 6

- **A-1b:** a captured real REQUEST and RESPONSE event for both shapes matches our fixtures,
  including whether MCP-target invocations also carry `GATEWAY_ARN` in the client context.
- **A-5:** whether an interceptor can *remove* an allowlisted client header, or only override it.
- **A-6:** gateway behaviour when the interceptor Lambda errors, times out or returns malformed
  output (fail-closed expected, not assumed).

## Sources

- https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-interceptors-types.html
- https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-interceptors-configuration.html
- https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/gateway-headers.html
