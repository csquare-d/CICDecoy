FROM cgr.dev/chainguard/go:latest AS build
WORKDIR /src
COPY . .
RUN go mod tidy && go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /cicdecoy .

FROM cgr.dev/chainguard/kubectl:latest

COPY --from=build /cicdecoy /usr/local/bin/cicdecoy

ENTRYPOINT ["cicdecoy"]
