#!/usr/bin/env bash
# Build the verified IaC tool images (ADR-0026 §2). Fails closed: any verification error aborts.
set -euo pipefail
cd "$(dirname "$0")/.."

TFLINT_VERSION=0.64.0
COSIGN=ghcr.io/sigstore/cosign/cosign@sha256:b03690aa52bfe94054187142fba24dc54137650682810633901767d8a3e15b31
ARCH=$(docker version --format '{{.Server.Arch}}')
OUT=build/iac
rm -rf "$OUT" && mkdir -p "$OUT/dl"

base="https://github.com/terraform-linters/tflint/releases/download/v${TFLINT_VERSION}"
for f in "tflint_linux_${ARCH}.zip" checksums.txt checksums.txt.keyless.sig checksums.txt.pem; do
  curl -sSfL --max-time 120 -o "$OUT/dl/$f" "$base/$f"
done

docker run --rm --network bridge -v "$PWD/$OUT/dl:/w:ro" "$COSIGN" verify-blob \
  --certificate /w/checksums.txt.pem --signature /w/checksums.txt.keyless.sig \
  --certificate-identity "https://github.com/terraform-linters/tflint/.github/workflows/release.yml@refs/tags/v${TFLINT_VERSION}" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com /w/checksums.txt

(cd "$OUT/dl" && grep " tflint_linux_${ARCH}.zip\$" checksums.txt | shasum -a 256 -c -)
unzip -q -o "$OUT/dl/tflint_linux_${ARCH}.zip" -d "$OUT"
docker build -q -f deploy/iac/tflint.Dockerfile -t "atf-iac/tflint:${TFLINT_VERSION}" .
docker build -q -f deploy/iac/checkov.Dockerfile -t atf-iac/checkov:3.3.20 .
echo "IaC tool images built from verified inputs"
