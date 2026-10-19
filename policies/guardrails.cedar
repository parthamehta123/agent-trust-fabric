// Platform guardrails (ADR-0022 §3). CODEOWNERS-reviewed. Cedar's forbid-overrides-permit
// semantics mean no generated per-agent permit can override these.

// Bundle review #2: never permit an empty tool request. In Cedar, X.containsAll([]) is true, so
// without this the per-agent permit and the user-scopes guardrail would both allow one; every
// decision point also refuses it, and this keeps that true for any future one.
@id("guardrail:non-empty-scopes")
forbid (principal, action == Atf::Action::"invoke_tool", resource)
when { context.scopes.isEmpty() };

// TM-TOOL-01: an agent may only request scopes the user it acts for actually holds.
@id("guardrail:user-scopes")
forbid (principal, action == Atf::Action::"invoke_tool", resource)
unless { context.user_scopes.containsAll(context.scopes) };

// ADR-0021 §4: privileged agents never use servers reached with a shared credential.
@id("guardrail:privileged-no-shared-credentials")
forbid (principal, action == Atf::Action::"invoke_tool", resource)
when { principal.tier == "privileged" && resource.delegation == "none" };

// ADR-0025 §2: a document is readable only in collections the *user* holds (kb.<c>.read).
@id("guardrail:user-collections")
forbid (principal, action == Atf::Action::"read_document", resource)
unless { context.user_collections.contains(resource.collection) };
