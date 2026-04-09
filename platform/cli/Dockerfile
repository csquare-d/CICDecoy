FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /cicdecoy .

FROM alpine:3.20
RUN apk add --no-cache kubectl
COPY --from=build /cicdecoy /usr/local/bin/cicdecoy
ENTRYPOINT ["cicdecoy"]
