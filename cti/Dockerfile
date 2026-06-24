# cti/collector/Dockerfile

FROM cgr.dev/chainguard/python:latest-dev AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

FROM cgr.dev/chainguard/python:latest

COPY --from=builder /home/nonroot/.local /home/nonroot/.local
ENV PYTHONUSERBASE=/home/nonroot/.local
ENV PATH="/home/nonroot/.local/bin:$PATH"

WORKDIR /app
COPY *.py ./

ENV NATS_URL=nats://nats:4222
ENV DB_DSN=postgresql://cicdecoy:cicdecoy@timescaledb:5432/cicdecoy

EXPOSE 9090

ENTRYPOINT ["python", "pipeline.py"]
