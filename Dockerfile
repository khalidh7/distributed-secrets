FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -o /out/secrets-server ./cmd/server && \
    CGO_ENABLED=0 go build -trimpath -o /out/secretsctl ./cmd/secretsctl

FROM alpine:3.21
RUN apk add --no-cache ca-certificates postgresql-client
COPY --from=build /out/secrets-server /usr/local/bin/secrets-server
COPY --from=build /out/secretsctl /usr/local/bin/secretsctl
USER 65532:65532
ENTRYPOINT ["secrets-server"]

