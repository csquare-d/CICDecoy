# CI/CDecoy Adapter — Multi-stage build
FROM golang:1.22-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /adapter ./cmd/adapter

# ── Runtime ────────────────────────────────────────────
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /adapter /usr/local/bin/adapter

# Non-root
RUN adduser -D -u 1000 adapter
USER adapter

ENTRYPOINT ["adapter"]
