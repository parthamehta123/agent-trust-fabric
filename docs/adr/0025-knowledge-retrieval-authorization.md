# ADR-0025: Knowledge base with retrieval-time authorization (Phase 5)

- **Status:** accepted
- **Date:** 2026-10-13
- **Deciders:** Partha Mehta
- **Threat-model refs:** TM-KB-01, TM-KB-02, TM-KB-03, TM-TOOL-04, AS-7, A-3

## Decisions

1. **Labels.**
   - Every document carries a `collection` and a `classification`.
   - Classifications are ordered: `public` (0) < `internal` (1) < `confidential` (2) <
     `restricted` (3).
   - Chunks inherit their document's labels.

2. **Who may read.** A retrieval for user U by agent A (optionally on behalf of an earlier
   agent, ADR-0024) may return a chunk only if:
   - its collection is in **U's collections**: from the delegated token's `kb.<collection>.read`
     scopes, which the IdP downscopes per user;
   - its collection is in **every actor's** knowledge grant (no amplification);
   - its classification rank is ≤ **every actor's** ceiling.

3. **Enforcement: pre-filter, then per-chunk re-check.**
   - The knowledge server derives the metadata filter **server-side** from the token and the
     bundle; the agent supplies only the query text and `top_k`.
   - Every returned chunk is then re-checked in Cedar (`read_document`, a `Document` with
     `collection` and `classification_rank`), with the user-collection guardrail and the chain
     rule.
   - A chunk that passes the filter but fails Cedar is dropped and audited as a **filter
     anomaly**. That would mean a filter bug or a backend divergence (A-3).

4. **Integration.**
   - The knowledge server is an **MCP server** enrolled behind the MCP gateway. It inherits
     two-person approval, digest pinning, SSRF pinning, Cedar `invoke_tool`, response scanning,
     chains and delegated tokens.
   - It validates the delegated token itself (issuer, audience, typ, `act` chain, ≤ 2 actors)
     and reads grants from the signed bundle.
   - Tool: `search(query, top_k ≤ 10)`.

5. **Ingestion.**
   - Each document arrives with an owner-supplied manifest: collection, classification, title,
     source.
   - Ingestion refuses:
     - unknown collections, and classifications above the collection's configured ceiling;
     - unlabelled documents;
     - documents whose content trips the scanner (injection- or secret-shaped). Nothing is
       indexed.
   - Provenance is recorded per chunk: source, SHA-256 of the document, `ingested_by`,
     `ingested_at`.

6. **Retrieval output.**
   - Only chunk text, title, collection and classification. Never embeddings, scores or
     internal source paths (AS-7).
   - A chunk that trips the response scanner is **dropped**, and the result reports only how
     many were withheld.

7. **Backends** sit behind a `VectorStore` interface.
   - Locally: an in-process store with deterministic hashing embeddings (no model download),
     built by the ingest CLI and mounted read-only.
   - In AWS: Bedrock Knowledge Bases `Retrieve`, with our filter translated to its metadata
     filter syntax, tested with Stubber (ED-13). A-3 is verified in Phase 6.

## Consequences

- Knowledge access gets the same identity, delegation and audit story as tools, with no new
  egress path.
- Agent records gain a `knowledge` grant (collections plus a classification ceiling).
