# syntax=docker/dockerfile:1

FROM golang:1.26-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOOS=linux GOCACHE=/root/.cache/go-build

# Source/UI changes reuse this dependency layer, including cached registry builds.
COPY go.mod go.sum ./
RUN go mod download

COPY cmd ./cmd
COPY internal ./internal
# Incremental compilation survives source changes on the same BuildKit builder.
RUN --mount=type=cache,target=/root/.cache/go-build \
    go build -mod=readonly -trimpath -ldflags="-s -w" -o /out/proxy ./cmd/proxy

FROM alpine:3.21
RUN apk add --no-cache ca-certificates && addgroup -S proxy && adduser -S -G proxy proxy \
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
