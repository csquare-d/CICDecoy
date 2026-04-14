# inference/Dockerfile

FROM python:3.12-slim AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-slim

RUN groupadd -r cicdecoy && useradd -r -g cicdecoy -d /app -s /sbin/nologin cicdecoy

COPY --from=builder /install /usr/local

WORKDIR /app
COPY *.py ./

RUN mkdir -p /etc/cicdecoy/profiles /etc/cicdecoy/prompts \
    && chown -R cicdecoy:cicdecoy /etc/cicdecoy /app

ENV MODEL_CONFIG=/etc/cicdecoy/model-config.yaml
ENV PROFILES_DIR=/etc/cicdecoy/profiles
ENV PROMPTS_DIR=/etc/cicdecoy/prompts

EXPOSE 8000
USER cicdecoy

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/v1/health')"

ENTRYPOINT ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
