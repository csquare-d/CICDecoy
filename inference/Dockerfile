# inference/Dockerfile

FROM cgr.dev/chainguard/python:latest-dev AS builder
WORKDIR /build
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

FROM cgr.dev/chainguard/python:latest

COPY --from=builder /home/nonroot/.local /home/nonroot/.local

WORKDIR /app
COPY *.py ./

ENV MODEL_CONFIG=/etc/cicdecoy/model-config.yaml
ENV PROFILES_DIR=/etc/cicdecoy/profiles
ENV PROMPTS_DIR=/etc/cicdecoy/prompts

EXPOSE 8000

ENTRYPOINT ["python", "-m", "uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
