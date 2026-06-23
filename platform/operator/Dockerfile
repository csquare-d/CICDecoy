# platform/operator/Dockerfile

FROM cgr.dev/chainguard/python:latest-dev AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM cgr.dev/chainguard/python:latest

COPY --from=builder /install /home/nonroot/.local

WORKDIR /app
COPY *.py ./

ENTRYPOINT ["python", "-m", "kopf", "run", "reconciler.py", "--verbose"]
