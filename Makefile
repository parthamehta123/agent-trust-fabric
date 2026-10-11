# Local stack (ADR-0015). `make up e2e down`.
SHELL := /bin/bash
export ATF_UID := $(shell id -u)
export ATF_GID := $(shell id -g)
PACKAGES := mock-idp gateway-emulator atf-agent-runtime atf-interceptor

.PHONY: certs wheels up e2e logs-scan down clean

certs:  ## ephemeral CA, service certs, client key, configs -> .local-ca/ (gitignored)
	uv run python -m devstack.bootstrap --out .local-ca

# Least privilege: each image gets only the first-party wheels it imports (never devstack).
WHEELS_mock-idp := mock_idp
WHEELS_gateway-emulator := gateway_emulator trustkit trustkit_http
WHEELS_atf-agent-runtime := atf_agent_runtime trustkit trustkit_http
WHEELS_atf-interceptor := atf_interceptor trustkit trustkit_http trustkit_aws

wheels:  ## hash-pinned requirements + per-service first-party wheels -> build/
	rm -rf build && mkdir -p build/req build/dist
	uv build --all-packages --wheel --out-dir build/dist
	for p in $(PACKAGES); do \
	  uv export --frozen --package $$p --no-emit-workspace --no-dev -o build/req/$$p.txt >/dev/null; \
	done
	$(foreach p,$(PACKAGES),mkdir -p build/wheels/$(p) && $(foreach w,$(WHEELS_$(p)),cp build/dist/$(w)-*.whl build/wheels/$(p)/ &&) true;)

up: certs wheels  ## build images and start the stack (waits for health)
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
