"""Base-image policy (TM-CP-03, ADR-0026 §2): every digest-pinned image we build on or run must be
either **signature-verified** or **at least 14 days old**.

Dependabot's cooldown covers new *versions*, but not same-tag digest refreshes (#13). This check
closes that gap.

* A signed image is verified with cosign (pinned image) against the identity in ``SIGNED``.
* Any other image must report a build time at least ``MIN_AGE_DAYS`` old on every platform we use.
  An unknowable build time (missing, or the 1970 epoch of reproducible builds) fails: unsigned
  *and* undatable is never acceptable.

Usage: ``python scripts/image_policy.py [--report-only]``. It needs Docker (``buildx
imagetools``) and network access, and exits non-zero on any violation.
"""

from __future__ import annotations

import datetime as dt
import json
import pathlib
import re
import subprocess
import sys
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from typing import Final

ROOT: Final = pathlib.Path(__file__).resolve().parents[1]
MIN_AGE_DAYS: Final = 14
PLATFORMS: Final = ("linux/amd64", "linux/arm64")
COSIGN: Final = (
    "ghcr.io/sigstore/cosign/cosign@sha256:"
    "b03690aa52bfe94054187142fba24dc54137650682810633901767d8a3e15b31"
)
SIGNED: Final[Mapping[str, tuple[str, str]]] = {
    # repository -> (certificate identity, OIDC issuer), from the publisher's documentation.
    "gcr.io/distroless/static-debian12": (
        "keyless@distroless.iam.gserviceaccount.com",
        "https://accounts.google.com",
    ),
}
_PINNED: Final = re.compile(
    r"(?P<repo>[a-z0-9][a-z0-9./_-]*(?::[A-Za-z0-9._-]+)?)@sha256:[0-9a-f]{64}"
)
_EPOCH_FLOOR: Final = dt.datetime(2000, 1, 1, tzinfo=dt.UTC)


@dataclass(frozen=True)
class Verdict:
    ref: str
    ok: bool
    why: str


def pinned_refs(root: pathlib.Path = ROOT) -> list[str]:
    """Digest-pinned image refs in Dockerfile ``FROM`` lines and compose ``image:`` keys."""
    refs: set[str] = set()
    for dockerfile in sorted(root.glob("deploy/**/*.Dockerfile")):
        for line in dockerfile.read_text().splitlines():
            if line.strip().upper().startswith("FROM "):
                m = _PINNED.search(line)
                if m:
                    refs.add(m.group(0))
    compose = root / "compose.yaml"
    if compose.exists():
        for line in compose.read_text().splitlines():
            if line.strip().startswith("image:"):
                m = _PINNED.search(line)
                if m:
                    refs.add(m.group(0))
    return sorted(refs)


def repository(ref: str) -> str:
    """``repo[:tag]@sha256:...`` -> ``repo`` (tag dropped)."""
    name = ref.split("@", 1)[0]
    last = name.rsplit("/", 1)[-1]
    return name.rsplit(":", 1)[0] if ":" in last else name


def judge_age(ref: str, created: Mapping[str, str | None], now: dt.datetime) -> Verdict:
    """Pure: ``created`` maps each platform we use to its build time (RFC 3339) or None."""
    missing = [p for p in PLATFORMS if p not in created]
    if missing and "single" not in created:
        return Verdict(ref, False, f"no build time for {', '.join(missing)}")
    times: list[dt.datetime] = []
    for value in created.values():
        if not value:
            return Verdict(ref, False, "build time missing")
        t = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if t < _EPOCH_FLOOR:
            return Verdict(ref, False, "build time unknowable (epoch) and image is not signed")
        times.append(t)
    newest = max(times)
    age = now - newest
    if age < dt.timedelta(days=MIN_AGE_DAYS):
        eligible = (newest + dt.timedelta(days=MIN_AGE_DAYS)).date().isoformat()
        return Verdict(ref, False, f"built {newest.date()} ({age.days} d); eligible {eligible}")
    return Verdict(ref, True, f"built {newest.date()} ({age.days} d)")


def _run(argv: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(argv, capture_output=True, text=True, check=False, timeout=180)  # noqa: S603


def build_times(
    ref: str, run: Callable[[list[str]], subprocess.CompletedProcess[str]] = _run
) -> dict[str, str | None]:
    r = run(["docker", "buildx", "imagetools", "inspect", ref, "--format", "{{json .Image}}"])
    if r.returncode != 0:
        raise RuntimeError(f"cannot inspect {ref}")
    doc = json.loads(r.stdout)
    if isinstance(doc, dict) and any("/" in k for k in doc):
        return {p: (doc.get(p) or {}).get("created") for p in PLATFORMS if p in doc}
    return {"single": doc.get("created") if isinstance(doc, dict) else None}


def verify_signature(
    ref: str, run: Callable[[list[str]], subprocess.CompletedProcess[str]] = _run
) -> Verdict:
    identity, issuer = SIGNED[repository(ref)]
    r = run(
        [
            "docker",
            "run",
            "--rm",
            COSIGN,
            "verify",
            ref,
            "--certificate-identity",
            identity,
            "--certificate-oidc-issuer",
            issuer,
        ]
    )
    if r.returncode == 0:
        return Verdict(ref, True, f"signature verified ({identity})")
    return Verdict(ref, False, "signature verification failed")


def evaluate(refs: Iterable[str], now: dt.datetime) -> list[Verdict]:
    out: list[Verdict] = []
    for ref in refs:
        try:
            out.append(
                verify_signature(ref)
                if repository(ref) in SIGNED
                else judge_age(ref, build_times(ref), now)
            )
        except (RuntimeError, ValueError, subprocess.TimeoutExpired) as e:
            out.append(Verdict(ref, False, str(e)))
    return out


def main(argv: list[str] | None = None) -> int:
    """``--report-only`` prints violations as GitHub warnings and exits 0. It's used during
    rollout, until the pins that predate this check comply (ADR-0026 §29)."""
    report_only = "--report-only" in (argv or [])
    verdicts = evaluate(pinned_refs(), dt.datetime.now(dt.UTC))
    for v in verdicts:
        print(f"{'ok  ' if v.ok else 'FAIL'} {repository(v.ref):45} {v.why}")
        if not v.ok and report_only:
            print(f"::warning title=image policy::{repository(v.ref)}: {v.why}")
    return 0 if report_only or all(v.ok for v in verdicts) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
