FROM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/proxy .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates && addgroup -S proxy && adduser -S -G proxy proxy
WORKDIR /app
COPY --from=build /out/proxy /app/proxy
USER proxy
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget -q -T 4 -O - http://127.0.0.1:${PORT:-8080}/health >/dev/null || exit 1
ENTRYPOINT ["/app/proxy"]
