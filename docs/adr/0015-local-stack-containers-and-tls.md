# ADR-0015: Local container stack (Lambda RIE, hardened images, ephemeral TLS)

- **Status:** accepted
- **Date:** 2026-10-12
- **Deciders:** Partha Mehta
- **Builds on:** ADR-0014 §2–§3
- **Amends:** ADR-0005 (the e2e stack uses the gateway emulator + Lambda RIE, not LocalStack;
  LocalStack does not emulate AgentCore)
- **Threat-model refs:** TM-RT-01, TM-ING-06, TM-EXC-01, TM-CP-03, RR-3

## Context

Phase 2b runs the ingress path as real processes over real TLS, packaged the way it will deploy.
A probe on 2026-10-12 against `public.ecr.aws/lambda/python:3.12` (pinned digest) established:

- RIE delivers Lambda client context from the **`X-Amz-Client-Context`** header (base64 JSON with
  a `custom` object), the same as the real Invoke API.
- `Lambda-Runtime-Client-Context` is ignored.
- The image runs with `--read-only` plus a `tmpfs /tmp`.

(Upstream issue aws/aws-lambda-runtime-interface-emulator#74, fixed by PR #110.)

## Decisions

1. **The interceptor ships as a Lambda container image.** The gateway emulator calls it through
   the RIE Invoke API with `X-Amz-Client-Context`.
   - That hop is plain HTTP, confined to the internal `core` network. In AWS it is the Lambda
     service's own channel, not a network path we operate (ED-8).
2. **Networks.**

   | Network | Members |
   |---|---|
   | `edge` | host ↔ gateway emulator only |
   | `core` | emulator ↔ interceptor ↔ mock IdP |
   | `agent` | emulator ↔ runtime only |

   The runtime publishes no ports, so local network isolation mirrors ADR-0014 §1.
3. **Ephemeral TLS.** `scripts/local_bootstrap.py` generates the following into `.local-ca/`
   (gitignored), with private keys at mode 0600:
   - an ECDSA P-256 CA: `CA:TRUE, pathlen:0`, `keyCertSign`, valid 7 days;
   - per-service leaf certificates: `serverAuth` EKU, exact DNS SANs, valid 7 days;
   - the front-end client's `private_key_jwt` key;
   - the mock IdP topology and the interceptor profiles.

   Services trust **only** that CA.
4. **`trustkit-http` gains `ca_bundle_path`.** It narrows trust to one CA bundle. TLS verification
   still cannot be turned off.
5. **`local:` signing keys are refused outside `ATF_ENV=local`.**
   - The interceptor's signer factory maps `arn:aws:kms:…` to `KmsEs256Signer` and `local:<name>` to
     `InMemoryEs256Signer`, loaded from a mounted key directory, **only** when `ATF_ENV=local`.
   - In any other environment a `local:` reference is a cold-start failure, so every request is
     denied (TM-EXC-01).
6. **The interceptor fails closed at cold start.** If dependencies can't be built (profiles, keys,
   environment), the module still exposes a handler. It denies every request with 503 and emits
   `config.invalid`. The handler is still never allowed to raise (ADR-0012 §3).
7. **Mock IdP HTTP shell.**
   - Rejects repeated form parameters with `invalid_request` (RFC 6749 §3.2), checked on the raw body
     before parsing.
   - Exposes `/_test/login` for e2e only.
   - Refuses to start unless `ATF_ENV=local`.
8. **Image baseline.**
   - Base images pinned by digest, multi-stage builds.
   - Non-root UID, read-only root filesystem with `tmpfs /tmp`, `cap_drop: [ALL]`,
     `no-new-privileges`.
   - No package manager or shell tooling added in final stages, and healthchecks.
9. **Developer UX.** `make certs | up | e2e | down | clean`. The compose e2e suite is marked
   `compose` and runs only when `ATF_COMPOSE=1`.
