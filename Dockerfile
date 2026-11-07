FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/proxy ./cmd/proxy

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
