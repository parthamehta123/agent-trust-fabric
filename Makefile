# Local stack (ADR-0015). `make up e2e down`.
SHELL := /bin/bash
export ATF_UID := $(shell id -u)
export ATF_GID := $(shell id -g)
PACKAGES := mock-idp gateway-emulator atf-agent-runtime atf-interceptor atf-mcp-gateway mock-mcp \
            atf-inference-gateway mock-llm atf-agent-registry atf-a2a-gateway \
            atf-knowledge-server

.PHONY: certs kb-index wheels up e2e logs-scan down clean iac-tools iac-validate

certs:  ## ephemeral CA, service certs, client key, configs -> .local-ca/ (gitignored)
	uv run python -m devstack.bootstrap --out .local-ca

kb-index: certs  ## ingest the sample corpus (ADR-0025 §5): any rejected document fails the build
	uv run python -m atf_knowledge_server.ingest --corpus deploy/local/corpus \
	  --config deploy/local/kb-collections.json --out .local-ca/kb/index.jsonl --ingested-by devstack

# Least privilege: each image gets only the first-party wheels it imports (never devstack).
WHEELS_mock-idp := mock_idp
WHEELS_gateway-emulator := gateway_emulator trustkit trustkit_http
WHEELS_atf-agent-runtime := atf_agent_runtime trustkit trustkit_http trustkit_policy trustkit_aws
WHEELS_atf-interceptor := atf_interceptor trustkit trustkit_http trustkit_aws trustkit_policy
WHEELS_atf-mcp-gateway := atf_mcp_gateway trustkit trustkit_http trustkit_aws trustkit_policy
WHEELS_mock-mcp := mock_mcp
WHEELS_atf-inference-gateway := atf_inference_gateway trustkit trustkit_http trustkit_aws trustkit_policy
WHEELS_atf-agent-registry := atf_agent_registry trustkit trustkit_http trustkit_aws trustkit_policy
WHEELS_atf-a2a-gateway := atf_a2a_gateway trustkit trustkit_http trustkit_aws trustkit_policy
WHEELS_atf-knowledge-server := atf_knowledge_server trustkit trustkit_http trustkit_aws trustkit_policy
WHEELS_mock-llm := mock_llm

wheels:  ## hash-pinned requirements + per-service first-party wheels -> build/
	rm -rf build && mkdir -p build/req build/dist
	uv build --all-packages --wheel --out-dir build/dist
	for p in $(PACKAGES); do \
	  uv export --frozen --package $$p --no-emit-workspace --no-dev -o build/req/$$p.txt >/dev/null; \
	done
	$(foreach p,$(PACKAGES),mkdir -p build/wheels/$(p) && $(foreach w,$(WHEELS_$(p)),cp build/dist/$(w)-*.whl build/wheels/$(p)/ &&) true;)

up: certs kb-index wheels  ## build images and start the stack (waits for health)
	docker compose up -d --build --wait

e2e:  ## run the HTTPS e2e suite against the running stack
	ATF_COMPOSE=1 uv run pytest -m compose tests/compose -v

logs-scan:  ## fail if any container log contains token- or key-shaped material (TM-ING-06)
	mkdir -p build && docker compose logs --no-color > build/compose.log
	@test -s build/compose.log || { echo "no logs captured: refusing to pass vacuously"; exit 1; }
	@! grep -nE 'eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.|PRIVATE KEY' build/compose.log
	@echo "logs clean: $$(wc -l < build/compose.log) lines scanned"

down:
	docker compose down -v --remove-orphans

clean: down
	rm -rf .local-ca build

# ---------------------------------------------------------------- IaC (ADR-0026). Nothing touches AWS.
TOFU    := ghcr.io/opentofu/opentofu@sha256:22cb52f6c5bf5c72a48a8f56d993d8df3e9462b1cdfb5db7e77143c87e8d159f
TFLINT  := atf-iac/tflint:0.64.0
CHECKOV := atf-iac/checkov:3.3.20
IAC_RUN := docker run --rm --user $(ATF_UID):$(ATF_GID) -e HOME=/tmp -e TF_PLUGIN_CACHE_DIR=/cache -e TFLINT_PLUGIN_DIR=/cache/tflint \
	-v $(CURDIR)/infra:/w/infra -v $(CURDIR)/policies:/w/policies:ro -v $(CURDIR)/build/iac-cache:/cache

iac-tools:  ## build the verified tflint/checkov images (signature + checksum checks, fail closed)
	scripts/iac-tools.sh

iac-validate:  ## fmt, init (providers only), validate, test, tflint, checkov (sandboxed, RR-8)
	mkdir -p build/iac-cache
	$(IAC_RUN) -w /w/infra $(TOFU) fmt -check -recursive
	$(IAC_RUN) -w /w/infra/envs/dev $(TOFU) init -backend=false -input=false
	$(IAC_RUN) -w /w/infra/envs/dev $(TOFU) validate
	$(IAC_RUN) -w /w/infra/envs/dev $(TOFU) test
	for mod in network kms dynamodb bundles budget ecr ecs_cluster alb ecs_service certs verified_access; do \
	  $(IAC_RUN) -w /w/infra/modules/$$mod $(TOFU) init -backend=false -input=false >/dev/null && \
	  $(IAC_RUN) -w /w/infra/modules/$$mod $(TOFU) test || exit 1; \
	done
	$(IAC_RUN) -w /w/infra $(TFLINT) --init --config /w/infra/.tflint.hcl
	$(IAC_RUN) -w /w/infra $(TFLINT) --recursive --config /w/infra/.tflint.hcl
	docker run --rm --network none --read-only --tmpfs /tmp --cap-drop ALL \
	  --security-opt no-new-privileges --user $(ATF_UID):$(ATF_GID) \
	  -v $(CURDIR)/infra:/data:ro $(CHECKOV) -d /data --quiet --compact --framework terraform --skip-download
