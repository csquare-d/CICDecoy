# CI/CDecoy — SIEM Forwarder
# Multi-stage build: compile in Go builder, run in distroless.
# Final image is ~15MB with zero attack surface.

# TODO(security): Pin to digest in production, e.g. golang:1.22-alpine@sha256:...
FROM golang:1.22-alpine AS builder

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /siem-forwarder .

# ── Runtime ─────────────────────────────────────────
# TODO(security): Pin to digest in production, e.g. gcr.io/distroless/static-debian12:nonroot@sha256:...
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /siem-forwarder /siem-forwarder

USER nonroot:nonroot

ENTRYPOINT ["/siem-forwarder"]
