# cti/collector/Dockerfile

FROM python:3.12-slim@sha256:d764629ce0ddd8c71fd371e9901efb324a95789d2315a47db7e4d27e78f1b0e9 AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.12-slim@sha256:d764629ce0ddd8c71fd371e9901efb324a95789d2315a47db7e4d27e78f1b0e9

RUN groupadd -r cicdecoy && useradd -r -g cicdecoy -d /app -s /sbin/nologin cicdecoy

COPY --from=builder /install /usr/local

WORKDIR /app
COPY *.py ./

RUN mkdir -p /var/lib/cicdecoy/feeds \
    && chown -R cicdecoy:cicdecoy /var/lib/cicdecoy /app

ENV NATS_URL=nats://nats:4222
ENV DB_DSN=postgresql://cicdecoy:cicdecoy@timescaledb:5432/cicdecoy

EXPOSE 9090
USER cicdecoy

ENTRYPOINT ["python", "pipeline.py"]
