# syntax=docker/dockerfile:1
# Interceptor packaged exactly as a Lambda container image (ADR-0015 §1). The AWS base image
# bundles the Runtime Interface Emulator used locally.
FROM public.ecr.aws/lambda/python:3.12@sha256:3856536f53e945debf4c90d0ff301cbaa837c07a4ab9b0e2c102c6e54ceb9762
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
COPY build/req/atf-interceptor.txt /tmp/req.txt
COPY build/wheels/atf-interceptor/ /tmp/wheels/
RUN pip install --require-hashes --no-deps -r /tmp/req.txt --target "${LAMBDA_TASK_ROOT}" \
 && pip install --no-deps /tmp/wheels/*.whl --target "${LAMBDA_TASK_ROOT}" \
 && rm -rf /tmp/req.txt /tmp/wheels
CMD ["atf_interceptor.lambda_main.handler"]
