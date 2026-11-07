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
the application behind a VPN/IP allowlist rather than leaving it unauthenticated.

## 4. Domain and HTTPS

Create a Dokploy domain that forwards to application port `8080` and enable
HTTPS. Point the domain's DNS record to the Dokploy host first.

Example endpoints:

```text
OpenAI base URL: https://api.example.com/v1
Admin panel:     https://api.example.com/admin
Health:          https://api.example.com/health
Metrics:         https://api.example.com/metrics
```

Do not create a direct public host-port mapping for `8080`; only Dokploy's
reverse proxy should reach it.

## 5. First login

Open `/admin`, enter `ADMIN_TOKEN`, and add AgentRouter keys. The browser keeps
the admin token only in `sessionStorage`; the server never returns full stored
keys.

## Updating

With automatic deployments enabled, a push to `main` triggers a rebuild. For a
manual deployment, use Dokploy's Redeploy action. Keep the `/data` volume
attached between deployments.
