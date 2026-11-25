FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS=linux
ARG TARGETARCH
WORKDIR /src
ENV CGO_ENABLED=0 \
    GOMODCACHE=/go/pkg/mod \
    GOCACHE=/go/build-cache

# Download modules and pre-compile all external + stdlib dependencies directly
# into the cached image layer. Unlike ephemeral --mount=type=cache volumes,
# keeping GOMODCACHE and GOCACHE in this layer guarantees ~1-2s incremental
# rebuilds across Dokploy, Docker Compose, and registry/GHA layer caches while
# adding zero bytes to the final runtime stage.
COPY go.mod go.sum ./
RUN go mod download && \
    mkdir -p cmd/_deps && \
    printf 'package main\nimport (\n\t_ "crypto/pbkdf2"\n\t_ "crypto/x509"\n\t_ "database/sql"\n\t_ "embed"\n\t_ "net/http"\n\t_ "net/netip"\n\t_ "github.com/jackc/pgx/v5/stdlib"\n\t_ "github.com/redis/go-redis/v9"\n\t_ "google.golang.org/genai"\n)\nfunc main() {}\n' > cmd/_deps/main.go && \
    GOOS="${TARGETOS:-linux}" GOARCH="${TARGETARCH:-$(go env GOARCH)}" \
    go build -mod=readonly -trimpath -ldflags="-s -w -buildid=" -o /dev/null ./cmd/_deps && \
    rm -rf cmd/_deps

COPY cmd ./cmd
COPY internal ./internal
RUN GOOS="${TARGETOS:-linux}" GOARCH="${TARGETARCH:-$(go env GOARCH)}" \
    go build -mod=readonly -trimpath -ldflags="-s -w -buildid=" -o /out/proxy ./cmd/proxy

FROM alpine:3.21
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
RUN addgroup -S proxy && adduser -S -G proxy -H -D proxy \
    && mkdir -p /data && chown proxy:proxy /data
LABEL org.opencontainers.image.source="https://github.com/kevji1337/Agentrouter-unified-proxy" \
      org.opencontainers.image.description="Unified AgentRouter Chat Completions and Responses API proxy" \
      org.opencontainers.image.licenses="MIT"
WORKDIR /app
COPY --from=build /out/proxy /app/proxy
VOLUME ["/data"]
USER proxy
EXPOSE 8080
HEALTHCHECK --interval=5s --timeout=3s --start-period=3s --retries=3 \
  CMD ["/app/proxy", "-healthcheck"]
ENTRYPOINT ["/app/proxy"]
