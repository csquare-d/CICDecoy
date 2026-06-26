# images/ssh-decoy/Dockerfile
#
# Multi-stage build for the SSH decoy container.
# Chainguard base for zero CVE OS layer.
# check=skip=SecretsUsedInArgOrEnv

FROM cgr.dev/chainguard/python:latest-dev AS builder

WORKDIR /build
COPY ssh-decoy/requirements.txt .
RUN pip install --no-cache-dir --target=/home/nonroot/deps -r requirements.txt
# Create writable data directory for host key storage
RUN mkdir -p /home/nonroot/cicdecoy-data

# ── Final stage ──────────────────────────────────────
FROM cgr.dev/chainguard/python:latest

# Copy installed packages (COPY runs as root → /opt/deps is world-readable)
COPY --from=builder /home/nonroot/deps /opt/deps
ENV PYTHONPATH=/opt/deps
ENV PATH="/opt/deps/bin:$PATH"

# Create /var/lib/cicdecoy owned by nonroot (65532) so host key generation works
# even when Docker named volumes are mounted (they inherit image dir ownership).
COPY --from=builder --chown=65532:65532 /home/nonroot/cicdecoy-data /var/lib/cicdecoy

# Copy source
WORKDIR /app
COPY ssh-decoy/*.py ./
COPY lib/honeytoken_registry.py ./

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
