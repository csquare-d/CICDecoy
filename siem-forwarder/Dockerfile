# CI/CDecoy — SIEM Forwarder
# Multi-stage build: compile in Go builder, run in Chainguard static.
# Final image has zero CVE OS layer.

FROM cgr.dev/chainguard/go:latest AS builder

WORKDIR /build
COPY . .
RUN go mod tidy && go mod download
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /siem-forwarder .

# ── Runtime ─────────────────────────────────────────
FROM cgr.dev/chainguard/static:latest

COPY --from=builder /siem-forwarder /siem-forwarder

ENTRYPOINT ["/siem-forwarder"]
