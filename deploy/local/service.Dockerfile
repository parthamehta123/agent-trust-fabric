# syntax=docker/dockerfile:1
# Shared image for the uvicorn services (mock-idp, gateway-emulator, agent-runtime). ADR-0015 §8.
# Inputs are produced by `make wheels`: hash-pinned requirements + locally built wheels.

FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1 AS build
ARG SERVICE
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /opt/venv
COPY build/req/${SERVICE}.txt /tmp/req.txt
COPY build/wheels/ /tmp/wheels/
RUN /opt/venv/bin/pip install --require-hashes --no-deps -r /tmp/req.txt \
 && /opt/venv/bin/pip install --no-deps /tmp/wheels/*.whl

FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
# No package-manager installs in the final stage; only the venv is copied in.
COPY --from=build /opt/venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
# Runs as the host UID/GID set by compose (non-root); see compose.yaml.
ENTRYPOINT ["uvicorn", "--factory", "--host", "0.0.0.0", "--port", "8443", \
            "--ssl-certfile", "/run/certs/tls.pem", "--ssl-keyfile", "/run/certs/tls.key", \
            "--no-server-header", "--no-proxy-headers"]
