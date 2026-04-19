# CI/CDecoy Adapter — Multi-stage build
# TODO(security): Pin to digest in production, e.g. golang:1.22-alpine@sha256:...
FROM golang:1.22-alpine AS builder

WORKDIR /src
COPY . .
RUN go mod tidy && go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o /adapter ./cmd/adapter

# ── Runtime ────────────────────────────────────────────
# TODO(security): Pin to digest in production, e.g. alpine:3.19@sha256:...
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /adapter /usr/local/bin/adapter

# Non-root
RUN adduser -D -u 1000 adapter
USER adapter

ENTRYPOINT ["adapter"]
