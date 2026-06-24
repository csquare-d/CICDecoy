# images/ssh-decoy/Dockerfile
#
# Multi-stage build for the SSH decoy container.
# Chainguard base for zero CVE OS layer.
# check=skip=SecretsUsedInArgOrEnv

FROM cgr.dev/chainguard/python:latest-dev AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --target=/home/nonroot/deps -r requirements.txt

# ── Final stage ──────────────────────────────────────
FROM cgr.dev/chainguard/python:latest

# Copy installed packages
COPY --from=builder /home/nonroot/deps /home/nonroot/deps
ENV PYTHONPATH=/home/nonroot/deps
ENV PATH="/home/nonroot/deps/bin:$PATH"

# Copy source
WORKDIR /app
COPY *.py ./

# Default host key location — a file path, not a secret
ENV HOST_KEY_PATH=/var/lib/cicdecoy/ssh_host_key
ENV DECOY_CONFIG=""
ENV DECOY_PORT=2222
ENV DECOY_NAME=ssh-decoy
ENV DECOY_HOSTNAME=localhost
ENV DECOY_TIER=2
ENV NATS_ENDPOINT=nats://nats:4222
ENV LOG_LEVEL=INFO

EXPOSE 2222
EXPOSE 9091

ENTRYPOINT ["python", "server.py"]
