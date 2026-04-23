FROM golang:1.22-alpine@sha256:1699c10032ca2582ec89a24a1312d986a3f094aed3d5c1147b19880afe40e052 AS build
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
