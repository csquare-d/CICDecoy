# ── Stage 1: Build React frontend ────────────────────
FROM cgr.dev/chainguard/node:latest AS frontend

WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY index.html vite.config.js ./
COPY src/ src/
RUN npm run build

# ── Stage 2: Install Python deps ────────────────────
FROM cgr.dev/chainguard/python:latest-dev AS backend-builder

WORKDIR /build
COPY requirements.txt ./
RUN pip install --no-cache-dir --user -r requirements.txt

# ── Stage 3: Minimal runtime ────────────────────────
FROM cgr.dev/chainguard/python:latest

COPY --from=backend-builder /home/nonroot/.local /home/nonroot/.local

WORKDIR /app

# Backend code
COPY main.py ./

# Built frontend from stage 1
COPY --from=frontend /app/static ./static

EXPOSE 8080

ENTRYPOINT ["python", "-m", "uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
