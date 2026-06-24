# platform/operator/Dockerfile

FROM cgr.dev/chainguard/python:latest-dev AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --target=/home/nonroot/deps -r requirements.txt \
    && chmod -R a+rX /home/nonroot/deps

FROM cgr.dev/chainguard/python:latest

COPY --from=builder /home/nonroot/deps /home/nonroot/deps
ENV PYTHONPATH=/home/nonroot/deps
ENV PATH="/home/nonroot/deps/bin:$PATH"

WORKDIR /app
COPY *.py ./

ENTRYPOINT ["python", "-m", "kopf", "run", "reconciler.py", "--verbose"]
