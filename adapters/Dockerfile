# CI/CDecoy Adapter — Multi-stage build
FROM golang:1.26-alpine@sha256:f85330846cde1e57ca9ec309382da3b8e6ae3ab943d2739500e08c86393a21b1 AS builder

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
