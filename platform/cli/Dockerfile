# TODO(security): Pin to digest in production, e.g. golang:1.22-alpine@sha256:...
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
RUN go mod tidy && go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /cicdecoy .

# TODO(security): Pin to digest in production, e.g. alpine:3.20@sha256:...
FROM alpine:3.20
RUN apk add --no-cache kubectl

# Non-root
RUN adduser -D -u 1000 cicdecoy
COPY --from=build /cicdecoy /usr/local/bin/cicdecoy

USER cicdecoy

ENTRYPOINT ["cicdecoy"]
