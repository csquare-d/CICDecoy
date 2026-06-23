# CI/CDecoy — SIEM Forwarder
# Multi-stage build: compile in Go builder, run in distroless.
# Final image is ~15MB with zero attack surface.

FROM golang:1.26-alpine@sha256:f85330846cde1e57ca9ec309382da3b8e6ae3ab943d2739500e08c86393a21b1 AS builder

WORKDIR /build
COPY . .
RUN go mod tidy && go mod download
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /siem-forwarder .

# ── Runtime ─────────────────────────────────────────
FROM gcr.io/distroless/static-debian12:nonroot@sha256:d093aa3e30dbadd3efe1310db061a14da60299baff8450a17fe0ccc514a16639

COPY --from=builder /siem-forwarder /siem-forwarder

USER nonroot:nonroot

ENTRYPOINT ["/siem-forwarder"]
