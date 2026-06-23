# images/http-decoy/Dockerfile
#
# Multi-stage build for the HTTP decoy container.
# Chainguard base for zero CVE OS layer.

FROM cgr.dev/chainguard/python:latest-dev AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# ── Final stage ──────────────────────────────────────
FROM cgr.dev/chainguard/python:latest

# Copy installed packages
COPY --from=builder /home/nonroot/.local /home/nonroot/.local

# Copy source
WORKDIR /app
COPY *.py ./
COPY routes/ /app/routes/
COPY templates/ /app/templates/
COPY static/ /app/static/

ENV HTTP_PORT=8080
ENV DECOY_NAME=http-decoy
ENV DECOY_HOSTNAME=localhost
ENV NATS_URL=nats://nats:4222
ENV METRICS_PORT=9092
ENV LOG_LEVEL=INFO

EXPOSE 8080
EXPOSE 9092

ENTRYPOINT ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
