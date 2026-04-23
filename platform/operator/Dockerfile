FROM python:3.12-slim@sha256:804ddf3251a60bbf9c92e73b7566c40428d54d0e79d3428194edf40da6521286
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .

# Security: run as non-root
RUN groupadd -r cicdecoy && useradd -r -g cicdecoy -d /app -s /sbin/nologin cicdecoy \
    && chown -R cicdecoy:cicdecoy /app

USER cicdecoy

ENTRYPOINT ["kopf", "run", "reconciler.py", "--verbose"]
