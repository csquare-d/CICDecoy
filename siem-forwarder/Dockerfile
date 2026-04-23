# CI/CDecoy — SIEM Forwarder
# Multi-stage build: compile in Go builder, run in distroless.
# Final image is ~15MB with zero attack surface.

FROM golang:1.22-alpine@sha256:1699c10032ca2582ec89a24a1312d986a3f094aed3d5c1147b19880afe40e052 AS builder

WORKDIR /build
COPY . .
RUN go mod tidy && go mod download
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /siem-forwarder .

# ── Runtime ─────────────────────────────────────────
FROM gcr.io/distroless/static-debian12:nonroot@sha256:a9329520abc449e3b14d5bc3a6ffae065bdde0f02667fa10880c49b35c109fd1

COPY --from=builder /siem-forwarder /siem-forwarder

USER nonroot:nonroot

ENTRYPOINT ["/siem-forwarder"]
