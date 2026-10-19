# Runbook: Okta preflight probes

Verify the Okta assumptions **before** any AWS spend:

| Assumption | Question |
|---|---|
| A-2 | Does the org issue an ID-JAG, and does a custom authorization server redeem it with the JWT-bearer grant? |
| A-12 | Can JWT-bearer (and token-exchange) output be DPoP-bound? |
| A-14 | Does DPoP client credentials (with Okta's nonce challenge) behave the way the agents expect? |
| A-15 | Do access tokens have the shape the `okta` validator profile expects, and does `uid` equal the ID token's `sub`? |
| A-16 | Does token exchange with an `actor_token` emit RFC 8693 `act`? |

The probes are opt-in (`ATF_OKTA_PROBES=1` + `ATF_OKTA_CONFIG`) and never run in CI. They only
request tokens; they never change the tenant. Their report (`build/okta-preflight.md`) holds
claim names, value shapes and error codes, never token material.

> **Use a throwaway tenant** (a free Okta Integrator account), never a production org. Okta's
> console labels change between releases: where a label differs, the **property** in bold is what
> matters.

## 1. Keys

```bash
make okta-probe-keys
```

This writes three P-256 private keys to `.okta-preflight/keys/` (gitignored, 0600) and prints three
public JWKs: `chat`, `agent`, `tool-gateway`. You paste each into its app in step 3. The private keys
never leave your machine. Use `--rotate` to replace them.

## 2. Custom authorization servers

Create three (Security → API → Authorization Servers). For each, add the scope, and an access
policy whose rule allows **only** the grant and client listed.

| Name | Audience | Scope | Rule: grant type, client |
|---|---|---|---|
| `atf-agent-alpha` | `api://atf-agent-alpha` | `agent.invoke` | **JWT Bearer** (the Cross App Access / ID-JAG grant), `atf-chat` |
| `atf-workload` | `api://atf-tool-gateway` | `tools.invoke` | **Client Credentials**, `atf-agent` |
| `atf-tool-tickets` | `api://atf-tool-tickets` | `tickets.read` | **Token Exchange**, `atf-tool-gateway` |

## 3. Apps

| App | Type | Settings |
|---|---|---|
| `atf-chat` | OIDC **Web** application | Grants: **Authorization Code** (and the **Token Exchange** grant Cross App Access needs to request an ID-JAG). Client authentication: **Public key / Private key**, paste the `chat` JWK. **Require PKCE**. Sign-in redirect URI: **`http://127.0.0.1:8765/callback`**. Assign your test user. |
| `atf-agent` | **API Services** | Client authentication: **Public key / Private key** (the `agent` JWK). **Require DPoP**. |
| `atf-tool-gateway` | **API Services** | Grant: **Token Exchange**. Client authentication: **Public key / Private key** (the `tool-gateway` JWK). |

## 4. Cross App Access

Connect `atf-chat` (the requesting app) to `atf-agent-alpha` (the resource) as Okta's Cross App
Access guide describes ([validate an ID-JAG](https://developer.okta.com/docs/guides/xaa-validate-id-jag/main/),
[XAA for an OIDC resource](https://developer.okta.com/blog/2026/08/24/xaa-oidc-resource)). If the
feature is listed under Settings → Features (Early Access), enable it there first.

## 5. Config

```bash
mkdir -p .okta-preflight
cp docs/runbooks/okta-preflight.config.example.json .okta-preflight/config.json
```

Fill in the org URL, the three issuers (`https://<tenant>.okta.com/oauth2/<server id>`), the
audiences and scopes from step 2, and the three client ids. The file holds no secrets; the config
model refuses unknown keys and any issuer that isn't a custom authorization server of the org.

## 6. Run

```bash
make okta-probes                    # discovery, workload token: A-2 (metadata), A-14, A-15
ATF_OKTA_LOGIN=1 make okta-probes   # adds the user path: A-2, A-15 (uid), A-16, A-12
```

With `ATF_OKTA_LOGIN=1`, your browser opens Okta's sign-in page. **Sign in yourself** as the test
user. The probe listens once on `127.0.0.1:8765`, checks `state` and `nonce`, and keeps the tokens
in memory for the run only.

A probe that Okta **refuses fails**: the assumption is refuted, with the OAuth error code as
evidence. A probe that's **skipped** didn't run, and the report says why (for example, a missing
key, no login, or an upstream probe failed).

## 7. Record

Copy the rows from `build/okta-preflight.md` into `docs/architecture.md`: strike through each
verified assumption with the date and evidence. Tick the A-15 and A-16 rows in
[`sandbox.md`](sandbox.md) too.

| If this fails | Then |
|---|---|
| A-2 | Cross App Access isn't available or isn't configured: no ingress T2. Check step 4 and the tenant's tier before anything else. |
| A-15 (`uid` ≠ ID token `sub`) | The mix-up defence would refuse every user. Re-open the `okta` profile's `uid` rule before the sandbox. |
| A-16 | Write the ADR-0016 fallback ADR (signed actor header) before the sandbox. |
| A-12 | Expected possibly: tool hops stay bearer (ADR-0028 §4, RR-10). |
| A-14 | Compare Okta's nonce behaviour with `trustkit.workload`; adjust before enabling `ATF_WORKLOAD_DPOP`. |

Afterwards, deactivate the three apps, or delete the throwaway tenant.
