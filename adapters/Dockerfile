# CI/CDecoy Adapter — Multi-stage build
FROM cgr.dev/chainguard/go:latest AS builder

WORKDIR /src
COPY . .
RUN go mod tidy && go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o /adapter ./cmd/adapter

# ── Runtime ────────────────────────────────────────────
FROM cgr.dev/chainguard/static:latest

COPY --from=builder /adapter /usr/local/bin/adapter

ENTRYPOINT ["adapter"]
