FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS build
ARG TARGETOS=linux
ARG TARGETARCH
WORKDIR /src
ENV CGO_ENABLED=0

# Mount Go module and compiler caches directly on the host BuildKit cache
# (zero 450MB layer tar/snapshot overhead) and pre-compile stdlib + third-party
# dependencies so subsequent deploys only compile changed local packages.
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download && \
    GOOS="${TARGETOS:-linux}" GOARCH="${TARGETARCH:-$(go env GOARCH)}" \
    go build -trimpath std \
      github.com/jackc/pgx/v5/stdlib \
      github.com/redis/go-redis/v9 \
      google.golang.org/genai && \
    mkdir -p -m 0700 /out/data

# Pre-compile internal/app Go code into GOCACHE before copying UI/OpenAPI assets,
# so HTML/CSS/docs edits skip compiling the 15k-line proxy package completely (~0.4s build).
COPY cmd ./cmd
COPY internal/app/*.go ./internal/app/
COPY internal/app/assets/assets.go ./internal/app/assets/assets.go
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    touch internal/app/assets/admin.html \
          internal/app/assets/openapi.json \
          internal/app/assets/docs.html \
          internal/app/assets/favicon.svg \
          internal/app/assets/favicon.ico && \
    GOOS="${TARGETOS:-linux}" GOARCH="${TARGETARCH:-$(go env GOARCH)}" \
    go build -mod=readonly -trimpath ./internal/app

COPY internal/app/assets ./internal/app/assets
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    GOOS="${TARGETOS:-linux}" GOARCH="${TARGETARCH:-$(go env GOARCH)}" \
    go build -mod=readonly -trimpath -ldflags="-s -w -buildid=" -o /out/proxy ./cmd/proxy

FROM alpine:3.21
LABEL org.opencontainers.image.source="https://github.com/kevji1337/Agentrouter-unified-proxy" \
      org.opencontainers.image.description="Unified AgentRouter Chat Completions, Responses, Anthropic, and GenAI proxy" \
      org.opencontainers.image.licenses="MIT"
WORKDIR /app
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build --chown=100:101 /out/data /data
COPY --from=build /out/proxy /app/proxy
VOLUME ["/data"]
USER 100:101
EXPOSE 8080
STOPSIGNAL SIGTERM
HEALTHCHECK --interval=2s --timeout=2s --start-period=2s --retries=3 \
  CMD ["/app/proxy", "-healthcheck"]
ENTRYPOINT ["/app/proxy"]
