# Deploy with Dokploy

Dokploy already provides reverse proxying, domains, and automatic TLS, so the
repository's optional Caddy deployment is not needed.

## 1. Create the application

Choose **GitHub** as the source:

```text
Repository: kevji1337/Agentrouter-unified-proxy
Branch: main
Build type: Dockerfile
Build context: .
Dockerfile path: Dockerfile
Container port: 8080
Health check path: /health
```

The public repository can be cloned without a GitHub token. Connect a GitHub
App/webhook if automatic deployments after pushes to `main` are desired.

## 2. Persistent storage

Create a persistent volume and mount it inside the application container:

```text
Container path: /data
```

Do not use ephemeral storage for `/data`: it contains the encrypted API key
pool. Back up the volume together with `KEY_STORE_SECRET`.

## 3. Environment variables

Add these values in Dokploy's Environment tab:

```dotenv
UPSTREAM_URL=https://agentrouter.org
LISTEN_ADDRESS=0.0.0.0
PORT=8080
SPOOF_PROFILE=claude-code

ADMIN_TOKEN=<long-random-value>
KEY_STORE_SECRET=<different-long-random-value>
KEY_STORE_PATH=/data/keys.json
KEY_SELECTION_MODE=pool-first
KEY_FAILOVER=true
KEY_COOLDOWN=5m
KEY_HEALTH_INTERVAL=5m

FORCE_SEQUENTIAL_TOOLS=true
STATELESS_RESPONSES=true
RESPONSE_HEADER_TIMEOUT=5m
SSE_IDLE_TIMEOUT=10m

STORAGE_BACKEND=postgres
DATABASE_URL=postgresql://agentrouter:PASSWORD@agentrouter-postgres:5432/agentrouter?sslmode=disable
REDIS_URL=redis://:PASSWORD@agentrouter-redis:6379/0
AUDIT_RETENTION_DAYS=30
STATE_SYNC_INTERVAL=5s
TELEGRAM_BOT_TOKEN=<telegram-bot-token>
TELEGRAM_CHAT_ID=<telegram-chat-id>
ALERT_COOLDOWN=5m
```

Optional multi-admin RBAC with TOTP can replace or complement `ADMIN_TOKEN`:

```dotenv
ADMIN_ACCOUNTS_JSON=[{"name":"owner","token":"long-token","role":"admin","totp_secret":"BASE32SECRET"},{"name":"auditor","token":"other-long-token","role":"viewer"}]
```

`admin` can mutate settings and keys; `viewer` can only read status, usage,
logs, and encrypted backups. When `totp_secret` is present, the login screen
also requires a current six-digit authenticator code.

For a public API, also configure:

```dotenv
PROXY_AUTH_TOKEN=<long-random-client-token>
```

Clients then need `X-Proxy-Token`. If an IDE cannot send custom headers, place
the application behind a VPN/IP allowlist during bootstrap. After deployment,
create a **Client API key** in `/admin`; it works in the IDE's standard API Key
field as `Authorization: Bearer arp_...` and is never forwarded upstream.

## 4. Domain and HTTPS

Create a Dokploy domain that forwards to application port `8080` and enable
HTTPS. Point the domain's DNS record to the Dokploy host first.

Example endpoints:

```text
OpenAI base URL:    https://api.example.com/v1
Anthropic base URL: https://api.example.com
Admin panel:        https://api.example.com/admin
Health:             https://api.example.com/health
Metrics:            https://api.example.com/metrics
```

Do not create a direct public host-port mapping for `8080`; only Dokploy's
reverse proxy should reach it.

## 5. First login

Open `/admin` over HTTPS and use `owner` + the saved password or Remember me.
Token login is no longer offered in the UI. Initial password setup/recovery for
a new installation remains available through the legacy administrative API.
See [admin-login.md](admin-login.md). Add upstream credentials with their
Base URL and API protocol. AgentRouter defaults to Responses; custom providers
can use native Chat Completions and generic profile. See [multi-upstream.md](multi-upstream.md)
for routing, production origin restrictions, compatibility and safe rollback.
New browser logins use HttpOnly Secure cookies, not sessionStorage tokens.
Keep persistent `/data`/PostgreSQL state and the same secrets across deployments
so remembered logins survive. The server never returns full stored upstream keys.

## Updating

With automatic deployments enabled, a push to `main` triggers a rebuild. For a
manual deployment, use Dokploy's Redeploy action. Keep the `/data` volume
attached between deployments.

### Faster Dockerfile rebuilds and rollouts

The Dockerfile separates `go mod download` and full dependency/stdlib pre-compilation
from application source compilation, storing both `/go/pkg/mod` and `/go/build-cache`
directly inside the builder stage layer (zero bytes in the final runtime image). When
`go.mod` and `go.sum` are unchanged, source or UI edits only compile `internal/app`
and `cmd/proxy` — even when exported image-layer caches (`type=gha` or registry caches)
are used or BuildKit cache mounts were pruned. Multi-arch builds also cross-compile
natively on `$BUILDPLATFORM` without slow QEMU compiler emulation.

For faster container replacement during deployments, `HEALTHCHECK` invokes the built-in
`["/app/proxy", "-healthcheck"]` probe on a 5-second interval instead of waiting 30
seconds for the first `sh`/`wget` poll. Runtime base image (`alpine:3.21`), non-root
user (`proxy`), `/data` volume, and TLS certificates remain unchanged.
