# CI/CDecoy Adapter — Multi-stage build
FROM golang:1.22-alpine@sha256:1699c10032ca2582ec89a24a1312d986a3f094aed3d5c1147b19880afe40e052 AS builder

WORKDIR /src
COPY . .
RUN go mod tidy && go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -o /adapter ./cmd/adapter

# ── Runtime ────────────────────────────────────────────
FROM alpine:3.19@sha256:6baf43584bcb78f2e5847d1de515f23499913ac9f12bdf834811a3145eb11ca1

RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /adapter /usr/local/bin/adapter

# Non-root
RUN adduser -D -u 1000 adapter
USER adapter

ENTRYPOINT ["adapter"]
