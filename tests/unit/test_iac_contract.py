"""Contracts between the Terraform and the code it configures (ADR-0012 §4, ADR-0026 §18).

The HCL validations restate rules the Python enforces at runtime. These tests read the HCL as
text and fail if either side changes without the other."""

from __future__ import annotations

import pathlib
import re

from trustkit.policy import FORBIDDEN_PROPAGATED_HEADERS, RESERVED_HEADERS

INFRA = pathlib.Path(__file__).resolve().parents[2] / "infra"


def _string_sets(hcl: str) -> list[set[str]]:
    """Every ``toset([...])`` / list literal of quoted strings in ``hcl``."""
    return [set(re.findall(r'"([^"]+)"', m)) for m in re.findall(r"\[([^\[\]]*)\]", hcl)]


def test_gateway_header_rules_mirror_trustkit() -> None:
    hcl = (INFRA / "modules/agentcore_gateway/variables.tf").read_text()
    sets = _string_sets(hcl)
    assert set(FORBIDDEN_PROPAGATED_HEADERS) in sets, "credential header list drifted"
    assert set(RESERVED_HEADERS) in sets, "reserved x-atf-* header list drifted"


def test_kb_filter_keys_stay_filterable() -> None:
    """``bedrock_kb.to_kb_filter`` filters on exactly these keys; the index must not hide them."""
    from atf_knowledge_server import bedrock_kb

    src = pathlib.Path(bedrock_kb.__file__).read_text()
    filter_keys = set(re.findall(r'"key": "([a-z_]+)"', src))
    assert filter_keys == {"collection", "classification_rank"}
    hcl = (INFRA / "modules/knowledge_base/main.tf").read_text()
    non_filterable = re.search(r"non_filterable = \[([^\]]*)\]", hcl)
    assert non_filterable is not None
    assert not filter_keys & set(re.findall(r'"([^"]+)"', non_filterable.group(1)))


def test_kb_export_keys_are_all_declared() -> None:
    """Every metadata key the ingest export writes is filterable or declared non-filterable."""
    import json

    from atf_knowledge_server.ingest import bedrock_objects

    from tests.knowledge.test_ingest import TEXT, manifest, run

    chunks = run((manifest(), TEXT)).chunks
    md = next(json.loads(b) for k, b in bedrock_objects(chunks, "") if k.endswith(".metadata.json"))
    written = set(md["metadataAttributes"])
    hcl = (INFRA / "modules/knowledge_base/main.tf").read_text()
    m = re.search(r"non_filterable = \[([^\]]*)\]", hcl)
    assert m is not None
    declared = set(re.findall(r'"([^"]+)"', m.group(1))) | {"collection", "classification_rank"}
    assert written <= declared, f"undeclared metadata keys: {sorted(written - declared)}"
