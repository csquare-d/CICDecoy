# inference/Dockerfile

FROM cgr.dev/chainguard/python:latest-dev AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --target=/opt/deps -r requirements.txt \
    && chmod -R a+rX /opt/deps

FROM cgr.dev/chainguard/python:latest

COPY --from=builder /opt/deps /opt/deps
ENV PYTHONPATH=/opt/deps
ENV PATH="/opt/deps/bin:$PATH"

WORKDIR /app
COPY *.py ./

ENV MODEL_CONFIG=/etc/cicdecoy/model-config.yaml
ENV PROFILES_DIR=/etc/cicdecoy/profiles
ENV PROMPTS_DIR=/etc/cicdecoy/prompts

EXPOSE 8000

ENTRYPOINT ["python", "-m", "uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
