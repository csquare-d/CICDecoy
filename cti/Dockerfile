# cti/collector/Dockerfile

FROM python:3.14-slim@sha256:3989a23fd2c28a34c7be819e488b958a10601d421ac25bea1e7a5d757365e2d5 AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.14-slim@sha256:3989a23fd2c28a34c7be819e488b958a10601d421ac25bea1e7a5d757365e2d5

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
