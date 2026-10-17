# syntax=docker/dockerfile:1
# tflint from the *signed release* binary (ADR-0026 §2). The binary is verified by
# scripts/iac-tools.sh (keyless-signed checksums + zip SHA-256) before this build runs.
FROM gcr.io/distroless/static-debian12@sha256:d75cdd72874d4790092fcb1b058493ecf6bb5bf2b2b897045b00ff01d91843f2
COPY --chmod=0555 build/iac/tflint /usr/local/bin/tflint
USER 65532:65532
WORKDIR /data
ENTRYPOINT ["/usr/local/bin/tflint"]
