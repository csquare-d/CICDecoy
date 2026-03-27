# images/ssh-decoy/Dockerfile
#
# Multi-stage build for the SSH decoy container.
# Final image is minimal: Python + dependencies + source.

FROM python:3.12-slim AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Final stage ──────────────────────────────────────
FROM python:3.12-slim

# Security: run as non-root
RUN groupadd -r cicdecoy && useradd -r -g cicdecoy -d /app -s /sbin/nologin cicdecoy

# Copy installed packages
COPY --from=builder /install /usr/local

# Copy source
WORKDIR /app
COPY *.py ./

# Create directories for config and keys
RUN mkdir -p /etc/cicdecoy /etc/cicdecoy/profiles /var/lib/cicdecoy \
    && chown -R cicdecoy:cicdecoy /etc/cicdecoy /var/lib/cicdecoy /app

# Default host key location (will be generated on first run if not mounted)
ENV HOST_KEY_PATH=/var/lib/cicdecoy/ssh_host_key
ENV DECOY_CONFIG=""
ENV DECOY_PORT=2222
ENV DECOY_NAME=ssh-decoy
ENV DECOY_HOSTNAME=localhost
ENV DECOY_TIER=2
ENV NATS_ENDPOINT=nats://nats:4222
ENV LOG_LEVEL=INFO

EXPOSE 2222

USER cicdecoy

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import socket; s=socket.socket(); s.settimeout(2); s.connect(('localhost',${DECOY_PORT})); s.close()"

ENTRYPOINT ["python", "server.py"]
