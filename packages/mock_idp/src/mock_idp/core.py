"""Mock enterprise IdP: an org authorization server plus N custom ASes, laid out like Okta.

TEST INFRASTRUCTURE ONLY (ADR-0005). It is deliberately **independent** of ``trustkit``: it
verifies JWTs with joserfc directly and its own checks, so a validator bug in ``trustkit`` cannot
be mirrored here and hidden.

Endpoints (dispatched by URL in ``MockIdp.token``):

* ``{base}/oauth2/v1/token``          org AS: RFC 8693 token exchange, ID token -> ID-JAG
* ``{base}/oauth2/{as_id}/v1/token``  custom AS: RFC 7523 JWT-bearer, ID-JAG -> T2 (RFC 9068)

Client authentication at both is ``private_key_jwt`` only (RFC 7523 §2.2):
``client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer``. The assertion
must have ``iss == sub == client_id``, ``aud == <that token endpoint>``, ``exp - iat <= 60``, be
unexpired, and carry a never-seen ``jti``.

Token exchange (org AS) additionally requires:

* ``requested_token_type == id-jag`` and ``subject_token_type == id_token``;
* subject ID token: signed by the org AS, unexpired, and **``aud`` contains the requesting
  client** (strict reading, ADR-0009);
* ``audience`` is a known custom-AS issuer -> else ``invalid_target``;
* the client's exchange policy allows that audience -> else ``unauthorized_client``;
* requested scopes ⊆ policy scopes for that audience -> else ``invalid_scope``.

The ID-JAG is signed by the org AS. Header ``typ: oauth-id-jag+jwt``; claims ``iss`` (org),
``sub``, ``aud`` (custom-AS issuer), ``client_id``, ``jti``, ``iat``, ``exp`` (60 s), ``scope``,
``auth_time``.

JWT-bearer (custom AS) additionally requires, of the ID-JAG assertion:

* signed by the org AS, ``typ == oauth-id-jag+jwt``, unexpired;
* ``aud == this AS's issuer``;
* ``client_id == the authenticated client``, and the client is registered at this AS;
* ``jti`` never redeemed before (TM-EXC-08).

T2 is an RFC 9068 JWT signed by the custom AS: header ``typ: at+jwt``; claims ``iss`` (custom
AS), ``sub``, ``aud`` (the AS's resource audience), ``client_id``, ``scope``, ``jti``, ``iat``,
``exp`` (300 s), ``auth_time``.

Errors follow RFC 6749 §5.2 / RFC 8693 §2.2.2: ``{"error": ..., "error_description": ...}``,
status 401 for ``invalid_client`` and 400 otherwise. Descriptions never echo token material.
"""

from __future__ import annotations

import base64
import json
import time
import uuid
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any, Final

from joserfc import jwt as jose_jwt
from joserfc.errors import JoseError
from joserfc.jwk import KeySet, RSAKey

GRANT_TOKEN_EXCHANGE: Final = "urn:ietf:params:oauth:grant-type:token-exchange"  # noqa: S105 - protocol URN, not a secret
GRANT_JWT_BEARER: Final = "urn:ietf:params:oauth:grant-type:jwt-bearer"
TOKEN_TYPE_ID_JAG: Final = "urn:ietf:params:oauth:token-type:id-jag"  # noqa: S105 - protocol URN, not a secret
TOKEN_TYPE_ID_TOKEN: Final = "urn:ietf:params:oauth:token-type:id_token"  # noqa: S105 - protocol URN, not a secret
GRANT_CLIENT_CREDENTIALS: Final = "client_credentials"
TOKEN_TYPE_ACCESS_TOKEN: Final = "urn:ietf:params:oauth:token-type:access_token"  # noqa: S105 - URN
CLIENT_ASSERTION_TYPE: Final = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
ID_JAG_TYP: Final = "oauth-id-jag+jwt"
ACCESS_TOKEN_TYP: Final = "at+jwt"  # noqa: S105 - protocol URN, not a secret
MAX_CLIENT_ASSERTION_LIFETIME_S: Final = 60
CLOCK_SKEW_S: Final = 60
LOGIN_TOKEN_TTL_S: Final = 3600


@dataclass(frozen=True)
class TokenResponse:
    status: int
    body: Mapping[str, Any]


@dataclass(frozen=True)
class ClientRegistration:
    client_id: str
    jwks: Mapping[str, Any]
    """Public JWKS used to verify this client's ``private_key_jwt`` assertions."""
    exchange_policy: Mapping[str, frozenset[str]] = field(default_factory=dict)
    """Org-AS policy: custom-AS issuer -> scopes this client may request an ID-JAG for."""
    groups: tuple[str, ...] = ()
    """Emitted as a ``groups`` claim in this client's client-credentials tokens (an Okta
    custom-AS groups claim, simplified). Used for the registry's admin roles (ADR-0021 §2)."""


@dataclass(frozen=True)
class AuthorizationServer:
    as_id: str
    resource_audience: str
    """``aud`` of access tokens this AS issues (the agent API, or the ingress API)."""
    clients: frozenset[str]
    """Clients registered at this AS (allowed to redeem ID-JAGs / receive tokens)."""
    agent_client_id: str | None = None
    """The agent whose API ``resource_audience`` is. A delegation exchange presenting a subject
    token from this AS must have this agent as its actor (AS-side confused-deputy guard)."""
    restricted_scopes: Mapping[str, frozenset[str]] = field(default_factory=dict)
    """Scope -> the users entitled to it (an Okta access-policy rule per group, simplified).
    An ID-JAG for this AS drops restricted scopes the user isn't entitled to (RFC 6749 §3.3
    downscoping); unlisted scopes are unrestricted."""


MAX_ACTORS = 2
"""Delegation chain cap (ADR-0024 §2): user -> A -> B, never further."""


def _act_depth(act: Any) -> int:
    """Number of actors in an ``act`` chain; malformed chains count as over the cap."""
    depth, node = 0, act
    while node is not None:
        if not isinstance(node, dict) or not isinstance(node.get("sub"), str):
            return MAX_ACTORS
        depth += 1
        node = node.get("act")
    return depth


class _OAuthError(Exception):
    def __init__(self, error: str, description: str, status: int = 400) -> None:
        self.error, self.description, self.status = error, description, status


def _unverified_claims(token: str) -> dict[str, Any]:
    """Only used to pick which client's JWKS to verify with; never trusted on its own."""
    try:
        seg = token.split(".")[1]
        claims = json.loads(base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)))
    except (IndexError, ValueError):
        raise _OAuthError("invalid_client", "malformed client assertion", 401) from None
    if not isinstance(claims, dict):
        raise _OAuthError("invalid_client", "malformed client assertion", 401)
    return claims


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _audiences(aud: Any) -> list[str]:
    if isinstance(aud, str):
        return [aud]
    if isinstance(aud, list) and all(isinstance(a, str) for a in aud):
        return aud
    return []


class MockIdp:
    def __init__(
        self,
        base_url: str = "https://idp.example.test",
        *,
        now: Callable[[], int] = lambda: int(time.time()),
        id_jag_ttl_s: int = 60,
        access_token_ttl_s: int = 300,
    ) -> None:
        self._base = base_url.rstrip("/")
        self._now = now
        self._id_jag_ttl = id_jag_ttl_s
        self._at_ttl = access_token_ttl_s
        # kid = RFC 7638 thumbprint: new key material always means a new kid, as with a real IdP
        # (ADR-0027). Fixed kids made a recreated mock look like a forger to every validator.
        self._org_key = RSAKey.generate_key(2048, private=True, auto_kid=True)
        self._servers: dict[str, AuthorizationServer] = {}
        self._server_keys: dict[str, RSAKey] = {}
        self._clients: dict[str, ClientRegistration] = {}
        self._client_keys: dict[str, KeySet] = {}
        self._seen: dict[tuple[str, str], int] = {}  # (namespace, jti) -> exp, pruned on insert

    def now(self) -> int:
        """The mock's clock (injected), so tests can build time-consistent inputs."""
        return self._now()

    # -- topology -----------------------------------------------------------------------------

    @property
    def org_issuer(self) -> str:
        return self._base

    def issuer(self, as_id: str) -> str:
        return f"{self._base}/oauth2/{as_id}"

    def token_endpoint(self, as_id: str | None = None) -> str:
        """``None`` -> the org AS token endpoint."""
        return (
            f"{self._base}/oauth2/v1/token" if as_id is None else f"{self.issuer(as_id)}/v1/token"
        )

    def register_client(self, client: ClientRegistration) -> None:
        self._clients[client.client_id] = client
        self._client_keys[client.client_id] = KeySet.import_key_set(dict(client.jwks))  # type: ignore[arg-type]

    def add_authorization_server(self, server: AuthorizationServer) -> None:
        self._servers[server.as_id] = server
        self._server_keys[server.as_id] = RSAKey.generate_key(2048, private=True, auto_kid=True)

    def jwks(self, as_id: str | None = None) -> dict[str, Any]:
        """Public JWKS of the org AS (``None``) or a custom AS."""
        key = self._org_key if as_id is None else self._server_keys[as_id]
        return {"keys": [key.as_dict(private=False)]}

    # -- test helpers ---------------------------------------------------------------------------

    def login(
        self,
        user: str,
        client_id: str,
        *,
        ingress_as_id: str,
        auth_time: int | None = None,
    ) -> tuple[str, str]:
        """Simulate an interactive login through ``client_id``.

        Returns ``(access_token, id_token)``: an RFC 9068 access token from ``ingress_as_id``
        (``cid`` = client) and an org-AS ID token (``aud`` = client, ``auth_time``).
        """
        now = self._now()
        auth_time = now if auth_time is None else auth_time
        server = self._servers[ingress_as_id]
        access_token = self._sign(
            self._server_keys[ingress_as_id],
            ACCESS_TOKEN_TYP,
            {
                "iss": self.issuer(ingress_as_id),
                "sub": user,
                "aud": server.resource_audience,
                "cid": client_id,
                "client_id": client_id,
                "iat": now,
                "exp": now + LOGIN_TOKEN_TTL_S,
                "jti": str(uuid.uuid4()),
                "auth_time": auth_time,
            },
        )
        id_token = self._sign(
            self._org_key,
            "JWT",
            {
                "iss": self.org_issuer,
                "sub": user,
                "aud": client_id,
                "iat": now,
                "exp": now + LOGIN_TOKEN_TTL_S,
                "jti": str(uuid.uuid4()),
                "auth_time": auth_time,
            },
        )
        return access_token, id_token

    # -- the token endpoint ----------------------------------------------------------------------

    def token(self, endpoint: str, form: Mapping[str, str]) -> TokenResponse:
        try:
            return self._dispatch(endpoint, form)
        except _OAuthError as e:
            return TokenResponse(e.status, {"error": e.error, "error_description": e.description})

    def _dispatch(self, endpoint: str, form: Mapping[str, str]) -> TokenResponse:
        if endpoint == self.token_endpoint():
            return self._token_exchange(endpoint, form)
        for as_id in self._servers:
            if endpoint == self.token_endpoint(as_id):
                grant = form.get("grant_type")
                if grant == GRANT_CLIENT_CREDENTIALS:
                    return self._client_credentials(as_id, endpoint, form)
                if grant == GRANT_TOKEN_EXCHANGE:
                    return self._delegation_exchange(as_id, endpoint, form)
                return self._jwt_bearer(as_id, endpoint, form)
        raise _OAuthError("invalid_request", "unknown token endpoint", 404)

    # -- grants ---------------------------------------------------------------------------------

    def _token_exchange(self, endpoint: str, form: Mapping[str, str]) -> TokenResponse:
        client_id = self._authenticate_client(endpoint, form)
        if form.get("grant_type") != GRANT_TOKEN_EXCHANGE:
            raise _OAuthError("unsupported_grant_type", "grant not supported here")
        if form.get("requested_token_type") != TOKEN_TYPE_ID_JAG:
            raise _OAuthError("invalid_request", "requested_token_type must be id-jag")
        if form.get("subject_token_type") != TOKEN_TYPE_ID_TOKEN:
            raise _OAuthError("invalid_request", "subject_token_type must be id_token")
        subject_token, audience = form.get("subject_token"), form.get("audience")
        if not subject_token or not audience:
            raise _OAuthError("invalid_request", "subject_token and audience are required")

        idt = self._verify(subject_token, self._org_key, "invalid_grant", "subject token invalid")
        if idt.header.get("typ") in (ID_JAG_TYP, ACCESS_TOKEN_TYP):
            raise _OAuthError("invalid_grant", "subject token is not an ID token")
        if idt.claims.get("iss") != self.org_issuer:
            raise _OAuthError("invalid_grant", "subject token issuer mismatch")
        self._require_unexpired(idt.claims, "invalid_grant", "subject token expired")
        if client_id not in _audiences(idt.claims.get("aud")):
            raise _OAuthError("invalid_grant", "subject token was not issued to this client")
        if not isinstance(idt.claims.get("sub"), str):
            raise _OAuthError("invalid_grant", "subject token has no subject")

        if audience not in {self.issuer(a) for a in self._servers}:
            raise _OAuthError("invalid_target", "unknown audience")
        allowed = self._clients[client_id].exchange_policy.get(audience)
        if allowed is None:
            raise _OAuthError("unauthorized_client", "client may not request this audience")
        requested = frozenset((form.get("scope") or "").split()) or allowed
        if not requested <= allowed:
            raise _OAuthError("invalid_scope", "requested scope exceeds policy")
        # User entitlements (ADR-0023 §1): drop restricted scopes this user isn't entitled to.
        # RFC 6749 §3.3 lets the AS grant fewer scopes; granting none is an error.
        server = next(srv for a, srv in self._servers.items() if self.issuer(a) == audience)
        sub = idt.claims["sub"]
        requested = frozenset(
            sc
            for sc in requested
            if sc not in server.restricted_scopes or sub in server.restricted_scopes[sc]
        )
        if not requested:
            raise _OAuthError("invalid_scope", "user is not entitled to any requested scope")

        now = self._now()
        scope = " ".join(sorted(requested))
        claims: dict[str, Any] = {
            "iss": self.org_issuer,
            "sub": idt.claims["sub"],
            "aud": audience,
            "client_id": client_id,
            "jti": str(uuid.uuid4()),
            "iat": now,
            "exp": now + self._id_jag_ttl,
            "scope": scope,
        }
        if _is_int(idt.claims.get("auth_time")):
            claims["auth_time"] = idt.claims["auth_time"]
        id_jag = self._sign(self._org_key, ID_JAG_TYP, claims)
        return TokenResponse(
            200,
            {
                "access_token": id_jag,
                "issued_token_type": TOKEN_TYPE_ID_JAG,
                "token_type": "N_A",
                "expires_in": self._id_jag_ttl,
                "scope": scope,
            },
        )

    def _jwt_bearer(self, as_id: str, endpoint: str, form: Mapping[str, str]) -> TokenResponse:
        client_id = self._authenticate_client(endpoint, form)
        server = self._servers[as_id]
        if client_id not in server.clients:
            raise _OAuthError("invalid_client", "client not registered at this server", 401)
        if form.get("grant_type") != GRANT_JWT_BEARER:
            raise _OAuthError("unsupported_grant_type", "grant not supported here")
        assertion = form.get("assertion")
        if not assertion:
            raise _OAuthError("invalid_request", "assertion is required")

        jag = self._verify(assertion, self._org_key, "invalid_grant", "assertion invalid")
        c = jag.claims
        if jag.header.get("typ") != ID_JAG_TYP:
            raise _OAuthError("invalid_grant", "assertion is not an ID-JAG")
        if c.get("iss") != self.org_issuer or c.get("aud") != self.issuer(as_id):
            raise _OAuthError("invalid_grant", "assertion issuer or audience mismatch")
        if c.get("client_id") != client_id:
            raise _OAuthError("invalid_grant", "assertion was issued to another client")
        exp = self._require_unexpired(c, "invalid_grant", "assertion expired")
        self._consume_jti(f"id-jag:{as_id}", c.get("jti"), exp, "invalid_grant")

        now = self._now()
        t2_claims: dict[str, Any] = {
            "iss": self.issuer(as_id),
            "sub": c["sub"],
            "aud": server.resource_audience,
            "client_id": client_id,
            "scope": c.get("scope", ""),
            "jti": str(uuid.uuid4()),
            "iat": now,
            "exp": now + self._at_ttl,
        }
        if _is_int(c.get("auth_time")):
            t2_claims["auth_time"] = c["auth_time"]
        t2 = self._sign(self._server_keys[as_id], ACCESS_TOKEN_TYP, t2_claims)
        return TokenResponse(
            200,
            {
                "access_token": t2,
                "token_type": "Bearer",
                "expires_in": self._at_ttl,
                "scope": t2_claims["scope"],
            },
        )

    def _client_credentials(
        self, as_id: str, endpoint: str, form: Mapping[str, str]
    ) -> TokenResponse:
        """Workload token: client registered at this AS, scopes within its policy for this AS.

        at+jwt with sub = client_id = the client, aud = the AS's resource audience.
        """
        client_id, server = self._registered_client(as_id, endpoint, form)
        scope = self._granted_scope(client_id, as_id, form)
        now = self._now()
        claims = {
            "iss": self.issuer(as_id),
            "sub": client_id,
            "client_id": client_id,
            "aud": server.resource_audience,
            "scope": scope,
            "jti": str(uuid.uuid4()),
            "iat": now,
            "exp": now + self._at_ttl,
        }
        groups = self._clients[client_id].groups
        if groups:
            claims["groups"] = sorted(groups)
        token = self._sign(self._server_keys[as_id], ACCESS_TOKEN_TYP, claims)
        return TokenResponse(
            200,
            {
                "access_token": token,
                "token_type": "Bearer",
                "expires_in": self._at_ttl,
                "scope": scope,
            },
        )

    def _delegation_exchange(
        self, as_id: str, endpoint: str, form: Mapping[str, str]
    ) -> TokenResponse:
        """RFC 8693 delegation at a tool AS (ADR-0016 §5).

        Requires: authenticated client registered here with a policy for this AS; subject and
        actor tokens both ``access_token`` type, both at+jwt signed by a custom AS of this IdP,
        unexpired; subject without ``act``; the subject's issuing AS ``agent_client_id`` equal to
        the actor's ``client_id``; ``resource`` = this AS's audience; scopes within policy.
        Issues at+jwt: sub = subject.sub, act = {sub: actor client}, client_id = caller.
        """
        client_id, server = self._registered_client(as_id, endpoint, form)
        rtt = form.get("requested_token_type")
        if rtt is not None and rtt != TOKEN_TYPE_ACCESS_TOKEN:
            raise _OAuthError("invalid_request", "requested_token_type must be access_token")
        for name in ("subject", "actor"):
            if (
                not form.get(f"{name}_token")
                or form.get(f"{name}_token_type") != TOKEN_TYPE_ACCESS_TOKEN
            ):
                raise _OAuthError("invalid_request", f"{name}_token must be an access_token")
        subject_as, subject = self._verify_issued_access_token(form["subject_token"])
        _, actor = self._verify_issued_access_token(form["actor_token"])
        prior = subject.get("act")
        if _act_depth(prior) >= MAX_ACTORS:  # ADR-0024 §2: at most two actors in a chain
            raise _OAuthError("invalid_grant", "delegation chain too long")
        actor_client = actor.get("client_id")
        if (
            not isinstance(actor_client, str)
            or self._servers[subject_as].agent_client_id != actor_client
        ):
            raise _OAuthError(
                "invalid_grant", "actor is not the agent the subject token was issued to"
            )
        audience = form.get("audience")
        if audience is not None and audience != self.issuer(as_id):
            raise _OAuthError("invalid_target", "unknown audience")
        if form.get("resource") != server.resource_audience:
            raise _OAuthError("invalid_target", "unknown resource")
        scope = self._granted_scope(client_id, as_id, form)
        now = self._now()
        claims = {
            "iss": self.issuer(as_id),
            "sub": subject["sub"],
            "aud": server.resource_audience,
            "client_id": client_id,
            # RFC 8693 §4.1: the current actor outermost, earlier actors nested.
            "act": {"sub": actor_client, **({"act": prior} if prior is not None else {})},
            "scope": scope,
            "jti": str(uuid.uuid4()),
            "iat": now,
            "exp": now + self._at_ttl,
        }
        token = self._sign(self._server_keys[as_id], ACCESS_TOKEN_TYP, claims)
        return TokenResponse(
            200,
            {
                "access_token": token,
                "issued_token_type": TOKEN_TYPE_ACCESS_TOKEN,
                "token_type": "Bearer",
                "expires_in": self._at_ttl,
                "scope": scope,
            },
        )

    def _registered_client(
        self, as_id: str, endpoint: str, form: Mapping[str, str]
    ) -> tuple[str, AuthorizationServer]:
        client_id = self._authenticate_client(endpoint, form)
        server = self._servers[as_id]
        if client_id not in server.clients:
            raise _OAuthError("invalid_client", "client not registered at this server", 401)
        return client_id, server

    def _granted_scope(self, client_id: str, as_id: str, form: Mapping[str, str]) -> str:
        allowed = self._clients[client_id].exchange_policy.get(self.issuer(as_id))
        if allowed is None:
            raise _OAuthError("unauthorized_client", "client has no policy at this server")
        requested = frozenset((form.get("scope") or "").split()) or allowed
        if not requested <= allowed:
            raise _OAuthError("invalid_scope", "requested scope exceeds policy")
        return " ".join(sorted(requested))

    def _verify_issued_access_token(self, token: str) -> tuple[str, dict[str, Any]]:
        """An at+jwt issued by one of *our* custom ASes, unexpired. -> (issuing as_id, claims)."""
        try:
            iss = _unverified_claims(token).get("iss")
        except _OAuthError:
            raise _OAuthError("invalid_grant", "token malformed") from None
        as_id = next((a for a in self._servers if self.issuer(a) == iss), None)
        if as_id is None:
            raise _OAuthError("invalid_grant", "token issuer unknown")
        verified = self._verify(token, self._server_keys[as_id], "invalid_grant", "token invalid")
        if verified.header.get("typ") != ACCESS_TOKEN_TYP:
            raise _OAuthError("invalid_grant", "token is not an access token")
        self._require_unexpired(verified.claims, "invalid_grant", "token expired")
        return as_id, dict(verified.claims)

    # -- client authentication (RFC 7523 §2.2) -------------------------------------------------

    def _authenticate_client(self, endpoint: str, form: Mapping[str, str]) -> str:
        if "client_secret" in form:
            raise _OAuthError("invalid_client", "only private_key_jwt is supported", 401)
        assertion = form.get("client_assertion")
        if form.get("client_assertion_type") != CLIENT_ASSERTION_TYPE or not assertion:
            raise _OAuthError("invalid_client", "client authentication required", 401)

        claimed = _unverified_claims(assertion).get("iss")
        if not isinstance(claimed, str) or claimed not in self._clients:
            raise _OAuthError("invalid_client", "unknown client", 401)
        verified = self._verify(
            assertion, self._client_keys[claimed], "invalid_client", "bad client assertion", 401
        )
        c = verified.claims
        if c.get("iss") != claimed or c.get("sub") != claimed:
            raise _OAuthError("invalid_client", "assertion iss/sub must equal client_id", 401)
        if c.get("aud") != endpoint:
            raise _OAuthError("invalid_client", "assertion audience must be this endpoint", 401)
        exp = self._require_unexpired(c, "invalid_client", "assertion expired", 401)
        iat = c.get("iat")
        if not isinstance(iat, int) or exp - iat > MAX_CLIENT_ASSERTION_LIFETIME_S:
            raise _OAuthError("invalid_client", "assertion lifetime too long", 401)
        if iat > self._now() + CLOCK_SKEW_S:
            raise _OAuthError("invalid_client", "assertion issued in the future", 401)
        if "client_id" in form and form["client_id"] != claimed:
            raise _OAuthError("invalid_client", "client_id does not match assertion", 401)
        self._consume_jti(f"client:{claimed}", c.get("jti"), exp, "invalid_client", 401)
        return claimed

    # -- primitives -------------------------------------------------------------------------------

    def _sign(self, key: RSAKey, typ: str, claims: dict[str, Any]) -> str:
        return jose_jwt.encode(
            {"alg": "RS256", "kid": key.kid, "typ": typ}, claims, key, algorithms=["RS256"]
        )

    @staticmethod
    def _verify(
        token: str, key: RSAKey | KeySet, error: str, description: str, status: int = 400
    ) -> jose_jwt.Token:
        try:
            verified = jose_jwt.decode(token, key, algorithms=["RS256", "ES256"])
        except (JoseError, ValueError, TypeError):
            raise _OAuthError(error, description, status) from None
        if not isinstance(verified.claims, dict):
            raise _OAuthError(error, description, status)
        return verified

    def _require_unexpired(
        self, claims: Mapping[str, Any], error: str, description: str, status: int = 400
    ) -> int:
        exp = claims.get("exp")
        if not isinstance(exp, int) or isinstance(exp, bool) or self._now() > exp:
            raise _OAuthError(error, description, status)
        return exp

    def _consume_jti(
        self, namespace: str, jti: Any, exp: int, error: str, status: int = 400
    ) -> None:
        if not isinstance(jti, str) or not jti:
            raise _OAuthError(error, "jti required", status)
        now = self._now()
        self._seen = {k: v for k, v in self._seen.items() if v >= now}
        if (namespace, jti) in self._seen:
            raise _OAuthError(error, "replayed jti", status)
        self._seen[(namespace, jti)] = exp
