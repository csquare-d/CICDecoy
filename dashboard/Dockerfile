# ── Stage 1: Build React frontend ────────────────────
# TODO(security): Pin to digest in production, e.g. node:20-slim@sha256:...
FROM node:20-slim AS frontend

WORKDIR /app
COPY package.json ./
RUN npm ci
COPY index.html vite.config.js ./
COPY src/ src/
RUN npm run build

# ── Stage 2: Python backend ─────────────────────────
# TODO(security): Pin to digest in production, e.g. python:3.12-slim@sha256:...
FROM python:3.12-slim

WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl && rm -rf /var/lib/apt/lists/*

# Python deps
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Backend code
COPY main.py ./

# Built frontend from stage 1
COPY --from=frontend /app/static ./static

# Security: run as non-root
RUN groupadd -r cicdecoy && useradd -r -g cicdecoy -d /app -s /sbin/nologin cicdecoy \
    && chown -R cicdecoy:cicdecoy /app

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD curl -sf http://localhost:8080/api/stats || exit 1

USER cicdecoy

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]