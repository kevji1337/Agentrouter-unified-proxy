FROM golang:1.26-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOOS=linux GOCACHE=/root/.cache/go-build

# Cache module downloads and pre-compile heavy dependencies.
# When code in cmd/ or internal/ changes, this layer is 100% CACHED,
# dropping build time from ~100s down to ~1-2s.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download && \
    printf 'package main\nimport (\n\t_ "github.com/jackc/pgx/v5/stdlib"\n\t_ "github.com/redis/go-redis/v9"\n\t_ "google.golang.org/genai"\n)\nfunc main() {}\n' > /tmp/deps.go && \
    go build -o /dev/null /tmp/deps.go && \
    rm /tmp/deps.go

COPY cmd ./cmd
COPY internal ./internal
# Fast incremental build reusing cached and pre-compiled dependency objects.
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go build -mod=readonly -ldflags="-s -w" -o /out/proxy ./cmd/proxy

FROM alpine:3.21
# Copy pre-installed CA certificates from the build stage with zero network calls,
# avoiding slow APK repository fetches.
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
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q -T 4 -O - http://127.0.0.1:${PORT:-8080}/health >/dev/null || exit 1
ENTRYPOINT ["/app/proxy"]
