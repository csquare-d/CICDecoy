# images/http-decoy/Dockerfile
#
# Multi-stage build for the HTTP decoy container.
# Chainguard base for zero CVE OS layer.

FROM cgr.dev/chainguard/python:latest-dev AS builder

WORKDIR /build
COPY http-decoy/requirements.txt .
RUN pip install --no-cache-dir --target=/home/nonroot/deps -r requirements.txt

# ── Final stage ──────────────────────────────────────
FROM cgr.dev/chainguard/python:latest

# Copy installed packages (COPY runs as root → /opt/deps is world-readable)
COPY --from=builder /home/nonroot/deps /opt/deps
ENV PYTHONPATH=/opt/deps
ENV PATH="/opt/deps/bin:$PATH"

# Copy source
WORKDIR /app
COPY http-decoy/*.py ./
COPY http-decoy/routes/ /app/routes/
COPY http-decoy/templates/ /app/templates/
COPY http-decoy/static/ /app/static/
COPY lib/honeytoken_registry.py ./

ENV HTTP_PORT=8080
ENV DECOY_NAME=http-decoy
ENV DECOY_HOSTNAME=localhost
ENV NATS_URL=nats://nats:4222
ENV METRICS_PORT=9092
ENV LOG_LEVEL=INFO

EXPOSE 8080
EXPOSE 9092

ENTRYPOINT ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
