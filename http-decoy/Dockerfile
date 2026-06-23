# images/http-decoy/Dockerfile
#
# Multi-stage build for the HTTP decoy container.
# Final image is minimal: Python + dependencies + source.

FROM python:3.12-slim@sha256:d764629ce0ddd8c71fd371e9901efb324a95789d2315a47db7e4d27e78f1b0e9 AS builder

WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Final stage ──────────────────────────────────────
FROM python:3.12-slim@sha256:d764629ce0ddd8c71fd371e9901efb324a95789d2315a47db7e4d27e78f1b0e9

# Security: run as non-root
RUN groupadd -r cicdecoy && useradd -r -g cicdecoy -d /app -s /sbin/nologin cicdecoy

# Copy installed packages
COPY --from=builder /install /usr/local

# Copy source
WORKDIR /app
COPY *.py ./
COPY routes/ /app/routes/
COPY templates/ /app/templates/
COPY static/ /app/static/

# Create directories for config
RUN mkdir -p /etc/cicdecoy \
    && chown -R cicdecoy:cicdecoy /etc/cicdecoy /app

ENV HTTP_PORT=8080
ENV DECOY_NAME=http-decoy
ENV DECOY_HOSTNAME=localhost
ENV NATS_URL=nats://nats:4222
ENV METRICS_PORT=9092
ENV LOG_LEVEL=INFO

EXPOSE 8080
EXPOSE 9092

USER cicdecoy

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import socket; s=socket.socket(); s.settimeout(2); s.connect(('localhost',${HTTP_PORT})); s.close()"

CMD python -m uvicorn main:app --host 0.0.0.0 --port ${HTTP_PORT:-8080}
