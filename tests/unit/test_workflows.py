"""GitHub workflow hygiene (TM-CP-03, ADR-0026 §25-26)."""

from __future__ import annotations

import pathlib
import re
from typing import Any

import pytest
import yaml

WORKFLOWS = sorted(
    (pathlib.Path(__file__).resolve().parents[2] / ".github/workflows").glob("*.yml")
)
SHA_PIN = re.compile(r"^[^@\s]+@[0-9a-f]{40}$")
OIDC_JOBS = {("plan.yml", "plan"), ("apply.yml", "apply")}


def load(path: pathlib.Path) -> dict[str, Any]:
    doc = yaml.safe_load(path.read_text())
    assert isinstance(doc, dict)
    # YAML 1.1 reads the bare key `on` as boolean True.
    doc["on"] = doc.pop(True, doc.get("on"))
    return doc


def steps(doc: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    return [(name, s) for name, job in doc["jobs"].items() for s in job.get("steps", [])]


def test_workflows_found() -> None:
    assert {p.name for p in WORKFLOWS} >= {"ci.yml", "plan.yml", "apply.yml"}


@pytest.mark.security
@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
class TestHygiene:
    def test_actions_pinned_to_full_sha(self, path: pathlib.Path) -> None:
        for _, s in steps(load(path)):
            if "uses" in s:
                assert SHA_PIN.fullmatch(s["uses"].split(" ")[0]), s["uses"]

    def test_least_privilege_token(self, path: pathlib.Path) -> None:
        assert load(path)["permissions"] == {"contents": "read"}

    def test_oidc_only_where_intended(self, path: pathlib.Path) -> None:
        for job_name, job in load(path)["jobs"].items():
            perms = job.get("permissions") or {}
            if perms.get("id-token") == "write":
                assert (path.name, job_name) in OIDC_JOBS, f"{path.name}:{job_name}"

    def test_no_privileged_triggers(self, path: pathlib.Path) -> None:
        triggers = load(path)["on"]
        assert "pull_request_target" not in triggers
        assert "workflow_run" not in triggers

    def test_checkout_does_not_persist_credentials(self, path: pathlib.Path) -> None:
        for _, s in steps(load(path)):
            if str(s.get("uses", "")).startswith("actions/checkout@"):
                assert s.get("with", {}).get("persist-credentials") is False

    def test_no_expressions_inside_run(self, path: pathlib.Path) -> None:
        """Untrusted context goes through `env:`, never interpolated into a script."""
        for _, s in steps(load(path)):
            assert "${{" not in str(s.get("run", "")), s.get("run")


# Contexts GitHub allows at job level (docs: "Contexts > Context availability"). `runner`, `steps`
# and `job` exist only inside steps; using them here makes the whole workflow file invalid.
JOB_LEVEL_CONTEXTS = {
    "env": {"github", "needs", "strategy", "matrix", "vars", "secrets", "inputs"},
    "if": {"github", "needs", "vars", "inputs"},
}
EXPR = re.compile(r"\$\{\{(.*?)\}\}")
CONTEXT = re.compile(r"(?<![\w.'])([a-z_]+)\.")


def contexts_in(value: object) -> set[str]:
    text = str(value)
    exprs = EXPR.findall(text) or ([text] if not isinstance(value, dict) else [])
    return {c for e in exprs for c in CONTEXT.findall(e)}


@pytest.mark.parametrize("path", WORKFLOWS, ids=lambda p: p.name)
def test_job_level_expressions_use_available_contexts(path: pathlib.Path) -> None:
    """Regression: `${{ runner.temp }}` in a job's `env:` broke plan.yml and apply.yml on GitHub."""
    for job_name, job in load(path)["jobs"].items():
        for key, allowed in JOB_LEVEL_CONTEXTS.items():
            if key in job:
                values = job[key].values() if isinstance(job[key], dict) else [job[key]]
                for v in values:
                    bad = contexts_in(v) - allowed
                    assert not bad, f"{path.name}:{job_name}.{key} uses {sorted(bad)}"


@pytest.mark.security
def test_apply_is_manual_gated_and_main_only() -> None:
    doc = load(next(p for p in WORKFLOWS if p.name == "apply.yml"))
    assert set(doc["on"]) == {"workflow_dispatch"}
    job = doc["jobs"]["apply"]
    assert job["environment"] == "sandbox"
    assert "refs/heads/main" in job["if"]
    assert "apply dev" in job["if"]
    assert doc["concurrency"]["cancel-in-progress"] is False


@pytest.mark.security
def test_plan_never_applies() -> None:
    doc = load(next(p for p in WORKFLOWS if p.name == "plan.yml"))
    runs = " ".join(str(s.get("run", "")) for _, s in steps(doc))
    assert "iac-plan" in runs
    assert "apply" not in runs


@pytest.mark.security
def test_dependabot_respects_the_minimum_age_and_python_pin() -> None:
    """ADR-0026 §2: nothing younger than 14 days; Python base images never jump a minor version."""
    doc = yaml.safe_load((WORKFLOWS[0].parents[1] / "dependabot.yml").read_text())
    for u in doc["updates"]:
        assert u["cooldown"]["default-days"] >= 14, u["package-ecosystem"]
        if u["package-ecosystem"] == "docker":
            ignored = {
                i["dependency-name"]
                for i in u.get("ignore", [])
                if "version-update:semver-minor" in i["update-types"]
            }
            assert "python" in ignored, u["directory"]
