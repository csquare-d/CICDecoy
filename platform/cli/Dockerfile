FROM golang:1.26-alpine@sha256:f85330846cde1e57ca9ec309382da3b8e6ae3ab943d2739500e08c86393a21b1 AS build
WORKDIR /src
COPY . .
RUN go mod tidy && go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /cicdecoy .

FROM alpine:3.20@sha256:d9e853e87e55526f6b2917df91a2115c36dd7c696a35be12163d44e6e2a4b6bc
RUN apk add --no-cache kubectl

# Non-root
RUN adduser -D -u 1000 cicdecoy
COPY --from=build /cicdecoy /usr/local/bin/cicdecoy

USER cicdecoy

ENTRYPOINT ["cicdecoy"]
