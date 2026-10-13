# syntax=docker/dockerfile:1
# tflint from the *signed release* binary (ADR-0026 §2). The binary is verified by
# scripts/iac-tools.sh (keyless-signed checksums + zip SHA-256) before this build runs.
FROM gcr.io/distroless/static-debian12@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --chmod=0555 build/iac/tflint /usr/local/bin/tflint
USER 65532:65532
WORKDIR /data
ENTRYPOINT ["/usr/local/bin/tflint"]
