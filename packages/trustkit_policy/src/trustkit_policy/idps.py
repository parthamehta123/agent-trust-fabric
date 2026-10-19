"""Which IdPs may issue an agent's T2 (ADR-0027 RFC self-review, finding #1).

An agent's registry spec names its T2 issuer and JWKS URL. Without a bound, one approval could
point an agent at an "IdP" its owner runs, and the gateways would accept user tokens that owner
signed. The bound is deployment config, ``ATF_TRUSTED_IDP_ORIGINS``: registry specs can't widen it.

* The issuer must be on a trusted origin (scheme, host and port; no path in the origin).
* The JWKS URL must be on the issuer's origin and under the issuer's path: keys are the issuer's
  own (RFC 8414 §2 / OIDC Discovery publish ``jwks_uri`` per issuer; Okta serves
  ``{issuer}/v1/keys``).

Checked at registry submission *and* when gateways build validators from a bundle.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final
from urllib.parse import urlsplit

ENV_VAR: Final = "ATF_TRUSTED_IDP_ORIGINS"


def _origin_and_path(url: str) -> tuple[str, str] | None:
    """``("https://host[:port]", path)`` for a plain https URL, else ``None``. Default port and
    host case are normalised; userinfo, query and fragment are refused."""
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return None
    host = parts.hostname
    if parts.scheme != "https" or not host or parts.username is not None:
        return None
    if parts.password is not None or parts.query or parts.fragment or "?" in url or "#" in url:
        return None
    netloc = host.lower() if port in (None, 443) else f"{host.lower()}:{port}"
    return f"https://{netloc}", parts.path


@dataclass(frozen=True)
class TrustedIdps:
    origins: frozenset[str]

    def __post_init__(self) -> None:
        if not self.origins:
            raise ValueError("at least one trusted IdP origin is required")
        for o in self.origins:
            parsed = _origin_and_path(o)
            if parsed is None or parsed != (o, "") or o != o.strip():
                raise ValueError("a trusted IdP origin is https://host[:port], nothing more")

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> TrustedIdps:
        """Comma- or space-separated origins. Missing or empty raises: no implicit trust."""
        raw = env.get(ENV_VAR, "").replace(",", " ").split()
        return cls(frozenset(o.rstrip("/") for o in raw))

    def allows(self, issuer: str, jwks_uri: str) -> bool:
        iss, keys = _origin_and_path(issuer), _origin_and_path(jwks_uri)
        if iss is None or keys is None or iss[0] not in self.origins or keys[0] != iss[0]:
            return False
        base = iss[1].rstrip("/")
        path = keys[1]
        dot_segment = ".." in path.split("/") or "%2e" in path.lower()
        return path.startswith(f"{base}/") and not dot_segment
