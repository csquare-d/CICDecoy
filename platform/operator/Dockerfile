# platform/operator/Dockerfile

FROM cgr.dev/chainguard/python:latest-dev AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --target=/opt/deps -r requirements.txt \
    && chmod -R a+rX /opt/deps

FROM cgr.dev/chainguard/python:latest

COPY --from=builder /opt/deps /opt/deps
ENV PYTHONPATH=/opt/deps
ENV PATH="/opt/deps/bin:$PATH"

WORKDIR /app
COPY *.py ./

ENTRYPOINT ["python", "-m", "kopf", "run", "reconciler.py", "--verbose"]
