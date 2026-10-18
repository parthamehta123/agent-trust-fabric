"""Base-image policy logic (TM-CP-03, ADR-0026 §2). Pure parts only; the live check runs in CI."""

from __future__ import annotations

import datetime as dt
import importlib.util
import pathlib
import subprocess
import sys
from typing import Any

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location("image_policy", ROOT / "scripts/image_policy.py")
assert _spec is not None
assert _spec.loader is not None
ip: Any = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = ip  # @dataclass resolves its module through sys.modules
_spec.loader.exec_module(ip)

NOW = dt.datetime(2026, 10, 19, tzinfo=dt.UTC)
REF = "python:3.12-slim@sha256:" + "a" * 64


def both(when: str | None) -> dict[str, str | None]:
    return {"linux/amd64": when, "linux/arm64": when}


@pytest.mark.security
class TestJudgeAge:
    def test_old_enough(self) -> None:
        assert ip.judge_age(REF, both("2026-10-01T00:00:00Z"), NOW).ok

    def test_too_new_names_the_eligible_date(self) -> None:
        v = ip.judge_age(REF, both("2026-10-11T13:00:00Z"), NOW)
        assert not v.ok
        assert "eligible 2026-10-25" in v.why

    def test_newest_platform_decides(self) -> None:
        v = ip.judge_age(
            REF, {"linux/amd64": "2026-09-01T00:00:00Z", "linux/arm64": "2026-10-15T00:00:00Z"}, NOW
        )
        assert not v.ok

    @pytest.mark.parametrize("when", [None, "", "1970-01-01T00:00:00Z"])
    def test_unknowable_age_fails_for_unsigned(self, when: str | None) -> None:
        assert not ip.judge_age(REF, both(when), NOW).ok

    def test_missing_platform_fails(self) -> None:
        assert not ip.judge_age(REF, {"linux/amd64": "2026-09-01T00:00:00Z"}, NOW).ok

    def test_single_platform_image(self) -> None:
        assert ip.judge_age(REF, {"single": "2026-09-01T00:00:00Z"}, NOW).ok


class TestRefs:
    @pytest.mark.parametrize(
        ("ref", "repo"),
        [
            ("python:3.12-slim@sha256:" + "a" * 64, "python"),
            (
                "public.ecr.aws/lambda/python:3.12@sha256:" + "a" * 64,
                "public.ecr.aws/lambda/python",
            ),
            (
                "gcr.io/distroless/static-debian12@sha256:" + "a" * 64,
                "gcr.io/distroless/static-debian12",
            ),
            ("localhost:5000/x@sha256:" + "a" * 64, "localhost:5000/x"),
        ],
    )
    def test_repository(self, ref: str, repo: str) -> None:
        assert ip.repository(ref) == repo

    def test_finds_every_pinned_base_image_in_the_repo(self) -> None:
        refs = ip.pinned_refs(ROOT)
        repos = {ip.repository(r) for r in refs}
        assert {
            "python",
            "public.ecr.aws/lambda/python",
            "gcr.io/distroless/static-debian12",
            "amazon/dynamodb-local",
        } <= repos
        assert all("@sha256:" in r for r in refs)

    def test_signed_images_never_use_the_age_rule(self) -> None:
        """distroless reports a 1970 build time (reproducible builds); it must go through cosign."""
        calls: list[list[str]] = []

        def fake_run(argv: list[str]) -> subprocess.CompletedProcess[str]:
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 0, "", "")

        ref = "gcr.io/distroless/static-debian12@sha256:" + "a" * 64
        v = ip.verify_signature(ref, run=fake_run)
        assert v.ok
        assert "--certificate-identity" in calls[0]
        assert ip.COSIGN in calls[0]

    def test_failed_signature_fails(self) -> None:
        def fake_run(argv: list[str]) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(argv, 1, "", "no matching signatures")

        assert not ip.verify_signature(
            "gcr.io/distroless/static-debian12@sha256:" + "a" * 64, run=fake_run
        ).ok
