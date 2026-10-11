# Interceptor event fixtures

`aws_doc_*.json` copy the payload shapes in the AWS AgentCore Gateway interceptor docs
(gateway-interceptors-types.html, retrieved 2026-10-11) verbatim. The only change is that
the HTTP examples' `<base64_encoded_body>` placeholder is replaced by a real base64 JSON body,
so it can be decoded.

Replace or extend these with **captured real events** before Phase 6 (assumption A-1b, ADR-0012).
