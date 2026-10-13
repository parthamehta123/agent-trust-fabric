# syntax=docker/dockerfile:1
# checkov from hash-pinned requirements (ADR-0026 §2). Runs sandboxed (RR-8): see Makefile.
FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1 AS build
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /opt/venv
COPY deploy/iac/checkov-requirements.txt /tmp/req.txt
RUN /opt/venv/bin/pip install --require-hashes --no-deps -r /tmp/req.txt

FROM python:3.12-slim@sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1
COPY --from=build /opt/venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 65532:65532
WORKDIR /data
ENTRYPOINT ["checkov"]
