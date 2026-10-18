"""Ingestion (ADR-0025 §5): bounded owner manifests, scan-before-index, provenance."""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys
import time
from collections import Counter
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Annotated, Any, Final

from pydantic import BaseModel, ConfigDict, StringConstraints, ValidationError

from atf_knowledge_server.store import Chunk, Provenance, embed, write_index
from trustkit.profiles import ScannerFailureMode
from trustkit.scanning import (
    ContentScanner,
    Direction,
    LocalRulesScanner,
    Verdict,
    scan_with_policy,
)
from trustkit_policy.grants import Classification, CollectionSlug, classification_rank

MAX_CHUNK_CHARS: Final = 1_200
MAX_DOC_CHARS: Final = 200_000


class Manifest(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    doc_id: Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9._-]{1,128}$")]
    title: Annotated[str, StringConstraints(min_length=1, max_length=256)]
    collection: CollectionSlug
    classification: Classification
    source: Annotated[str, StringConstraints(min_length=1, max_length=512)]


class CollectionsConfig(BaseModel):
    """Platform config: known collections and each one's classification ceiling."""

    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)

    collections: dict[CollectionSlug, Classification]


class Rejection(StrEnum):
    MANIFEST_INVALID = "manifest_invalid"
    UNKNOWN_COLLECTION = "unknown_collection"
    ABOVE_CEILING = "above_ceiling"
    EMPTY_OR_TOO_LARGE = "empty_or_too_large"
    CONTENT_BLOCKED = "content_blocked"
    DUPLICATE_DOC_ID = "duplicate_doc_id"


@dataclass(frozen=True)
class IngestReport:
    chunks: tuple[Chunk, ...]
    rejected: Mapping[str, Rejection] = field(default_factory=dict)
    """doc_id (or ``#<index>`` when the manifest itself is invalid) -> reason. No content."""


def chunk_text(text: str, max_chars: int = MAX_CHUNK_CHARS) -> list[str]:
    """Paragraph-first chunking; no chunk exceeds ``max_chars``; whitespace-only dropped."""
    out: list[str] = []
    for para in text.split("\n\n"):
        para = para.strip()
        while len(para) > max_chars:
            cut = para.rfind(" ", 0, max_chars)
            cut = cut if cut > 0 else max_chars
            out.append(para[:cut].strip())
            para = para[cut:].strip()
        if para:
            out.append(para)
    return [c for c in out if c]


def ingest_documents(
    documents: Sequence[tuple[Mapping[str, object], str]],
    *,
    config: CollectionsConfig,
    scanner: ContentScanner,
    ingested_by: str,
    now: Callable[[], int],
) -> IngestReport:
    """Validate, scan, chunk, embed, label. A rejected document contributes nothing."""
    rejected: dict[str, Rejection] = {}
    parsed: list[tuple[int, Manifest, str]] = []
    for i, (raw, text) in enumerate(documents):
        try:
            parsed.append((i, Manifest.model_validate_json(json.dumps(raw)), text))
        except (ValidationError, TypeError, ValueError):
            rejected[f"#{i}"] = Rejection.MANIFEST_INVALID
    counts = Counter(m.doc_id for _, m, _ in parsed)

    chunks: list[Chunk] = []
    for _, m, text in parsed:
        reason = _check(m, text, config, scanner, duplicate=counts[m.doc_id] > 1)
        if reason is not None:
            rejected[m.doc_id] = reason
            continue
        digest = hashlib.sha256(text.encode()).hexdigest()
        prov = Provenance(
            source=m.source, sha256=digest, ingested_by=ingested_by, ingested_at=now()
        )
        for n, piece in enumerate(chunk_text(text)):
            chunks.append(
                Chunk(
                    chunk_id=f"{m.doc_id}:{n}",
                    doc_id=m.doc_id,
                    title=m.title,
                    text=piece,
                    collection=m.collection,
                    classification=m.classification,
                    provenance=prov,
                    vector=embed(f"{m.title} {piece}"),
                )
            )
    return IngestReport(chunks=tuple(chunks), rejected=rejected)


def _check(
    m: Manifest, text: str, config: CollectionsConfig, scanner: ContentScanner, *, duplicate: bool
) -> Rejection | None:
    if duplicate:
        return Rejection.DUPLICATE_DOC_ID
    ceiling = config.collections.get(m.collection)
    if ceiling is None:
        return Rejection.UNKNOWN_COLLECTION
    if classification_rank(m.classification) > classification_rank(ceiling):
        return Rejection.ABOVE_CEILING
    if not text.strip() or len(text) > MAX_DOC_CHARS:
        return Rejection.EMPTY_OR_TOO_LARGE
    outcome = scan_with_policy(
        scanner,
        text,
        direction=Direction.RESPONSE,  # the corpus is content agents will later receive
        failure_mode=ScannerFailureMode.CLOSED,
        timeout_s=2.0,
    )
    # ADR-0025 §5: injection- or secret-shaped content (BLOCK) never enters the index; a scanner
    # failure is a BLOCK too (fail closed). PII (REDACT) may be stored: it is masked at retrieval.
    if outcome.result.verdict is Verdict.BLOCK:
        return Rejection.CONTENT_BLOCKED
    return None


def bedrock_objects(chunks: Sequence[Chunk], prefix: str) -> list[tuple[str, bytes]]:
    """The S3 layout for a Bedrock KB data source with ``chunking_strategy = NONE`` (ADR-0026
    §18): one object per *our* chunk plus a ``.metadata.json`` sidecar, so chunk ids, labels and
    provenance survive into ``Retrieve`` results exactly as the local store has them.
    ``collection`` and ``classification_rank`` are the filterable keys (``bedrock_kb``)."""
    base = prefix.strip("/")
    out: list[tuple[str, bytes]] = []
    for c in chunks:
        n = c.chunk_id.rsplit(":", 1)[1]
        key = f"{base}/{c.doc_id}/{n}.txt" if base else f"{c.doc_id}/{n}.txt"
        attrs = {
            "chunk_id": c.chunk_id,
            "doc_id": c.doc_id,
            "title": c.title,
            "collection": c.collection,
            "classification": c.classification,
            "classification_rank": classification_rank(c.classification),
            "source": c.provenance.source,
            "sha256": c.provenance.sha256,
            "ingested_by": c.provenance.ingested_by,
            "ingested_at": c.provenance.ingested_at,
        }
        out.append((key, c.text.encode()))
        out.append((f"{key}.metadata.json", json.dumps({"metadataAttributes": attrs}).encode()))
    return out


def _s3_target(uri: str) -> tuple[str, str]:
    bucket, _, prefix = uri.removeprefix("s3://").partition("/")
    if not uri.startswith("s3://") or not bucket:
        raise ValueError("--out-s3 must be s3://bucket[/prefix]")
    return bucket, prefix


def main(argv: Sequence[str] | None = None) -> int:
    """``python -m atf_knowledge_server.ingest --corpus DIR --config collections.json
    (--out index.jsonl | --out-s3 s3://bucket/prefix) --ingested-by NAME``. Each document is
    ``<name>.txt`` with a ``<name>.json`` manifest. Exits non-zero if anything was rejected (and
    writes nothing). ``--out-s3`` writes the Bedrock KB source layout (``bedrock_objects``); in
    AWS only the ingest role may write that bucket (ADR-0026 §18)."""
    ap = argparse.ArgumentParser(description="Ingest a labelled corpus into a knowledge index.")
    ap.add_argument("--corpus", type=pathlib.Path, required=True)
    ap.add_argument("--config", type=pathlib.Path, required=True)
    out = ap.add_mutually_exclusive_group(required=True)
    out.add_argument("--out", type=pathlib.Path)
    out.add_argument("--out-s3")
    ap.add_argument("--ingested-by", required=True)
    args = ap.parse_args(argv)
    target = _s3_target(args.out_s3) if args.out_s3 else None
    config = CollectionsConfig.model_validate_json(args.config.read_text())
    docs: list[tuple[Mapping[str, object], str]] = []
    for txt in sorted(args.corpus.glob("*.txt")):
        mpath = txt.with_suffix(".json")
        manifest: object = json.loads(mpath.read_text()) if mpath.exists() else None
        docs.append((manifest if isinstance(manifest, dict) else {}, txt.read_text()))
    report = ingest_documents(
        docs,
        config=config,
        scanner=LocalRulesScanner(),
        ingested_by=args.ingested_by,
        now=lambda: int(time.time()),
    )
    if report.rejected:
        for doc, reason in sorted(report.rejected.items()):
            print(f"rejected {doc}: {reason.value}", file=sys.stderr)
        return 1
    if target is None:
        write_index(report.chunks, args.out)
    else:
        try:
            _put_all(target, bedrock_objects(report.chunks, target[1]))
        except EmptyCorpusError as e:
            print(f"refused: {e}", file=sys.stderr)
            return 1
    print(f"indexed {len(report.chunks)} chunks from {len(docs)} documents")
    return 0


_LAYOUT: Final = re.compile(r"^[A-Za-z0-9._-]{1,128}/[0-9]+\.txt(\.metadata\.json)?$")
"""``<doc_id>/<n>.txt`` and its sidecar: the only objects this tool ever deletes."""


class EmptyCorpusError(ValueError):
    """A sync that would delete every chunk is refused: an empty export is far more likely a
    mistake (wrong directory, failed checkout) than an intentional wipe."""


def sync_objects(
    s3: Any, bucket: str, prefix: str, objects: Sequence[tuple[str, bytes]]
) -> tuple[int, int]:
    """Make ``prefix`` hold exactly ``objects`` (ADR-0026 §18): upload everything first, then
    delete objects in our layout that the export no longer produces, so withdrawn documents
    leave the KB on the next data-source sync (``data_deletion_policy = DELETE``).

    Returns ``(uploaded, deleted)``. Deletes happen only after every upload succeeded, and never
    outside the layout or the prefix."""
    if not objects:
        raise EmptyCorpusError("refusing to sync an empty export (it would delete the corpus)")
    base = prefix.strip("/")
    root = f"{base}/" if base else ""
    for key, body in objects:
        s3.put_object(Bucket=bucket, Key=key, Body=body)
    wanted = {key for key, _ in objects}
    stale: list[str] = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket, Prefix=root):
        for item in page.get("Contents", []):
            key = str(item["Key"])
            if key not in wanted and _LAYOUT.fullmatch(key[len(root) :]):
                stale.append(key)
    for i in range(0, len(stale), 1000):
        batch = [{"Key": k} for k in stale[i : i + 1000]]
        s3.delete_objects(Bucket=bucket, Delete={"Objects": batch, "Quiet": True})
    return len(objects), len(stale)


def _put_all(target: tuple[str, str], objects: Sequence[tuple[str, bytes]]) -> None:
    """Sync with the ingest role; the bucket's default SSE-KMS key encrypts each object."""
    import boto3

    uploaded, deleted = sync_objects(boto3.client("s3"), target[0], target[1], objects)
    print(f"uploaded {uploaded} objects; removed {deleted} withdrawn")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
