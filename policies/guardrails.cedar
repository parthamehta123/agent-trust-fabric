// Platform guardrails (ADR-0022 §3). CODEOWNERS-reviewed. Cedar's forbid-overrides-permit
// semantics mean no generated per-agent permit can override these.

// TM-TOOL-01: an agent may only request scopes the user it acts for actually holds.
@id("guardrail:user-scopes")
forbid (principal, action == Atf::Action::"invoke_tool", resource)
unless { context.user_scopes.containsAll(context.scopes) };

// ADR-0021 §4: privileged agents never use servers reached with a shared credential.
@id("guardrail:privileged-no-shared-credentials")
forbid (principal, action == Atf::Action::"invoke_tool", resource)
when { principal.tier == "privileged" && resource.delegation == "none" };
