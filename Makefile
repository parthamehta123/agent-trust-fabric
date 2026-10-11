# Local stack (ADR-0015). `make up e2e down`.
SHELL := /bin/bash
export ATF_UID := $(shell id -u)
export ATF_GID := $(shell id -g)
PACKAGES := mock-idp gateway-emulator atf-agent-runtime atf-interceptor

.PHONY: certs wheels up e2e down clean

certs:  ## ephemeral CA, service certs, client key, configs -> .local-ca/ (gitignored)
	uv run python -m devstack.bootstrap --out .local-ca

wheels:  ## hash-pinned requirements + locally built wheels -> build/
	rm -rf build && mkdir -p build/req build/wheels
	uv build --all-packages --wheel --out-dir build/wheels
	for p in $(PACKAGES); do \
	  uv export --frozen --package $$p --no-emit-workspace --no-dev -o build/req/$$p.txt >/dev/null; \
	done

up: certs wheels  ## build images and start the stack (waits for health)
	docker compose up -d --build --wait

e2e:  ## run the HTTPS e2e suite against the running stack
	ATF_COMPOSE=1 uv run pytest -m compose tests/compose -v

down:
	docker compose down -v --remove-orphans

clean: down
	rm -rf .local-ca build
