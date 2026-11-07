# Hosting on a VPS

The proxy can run as a private API gateway on a Linux VPS. Do not expose port
`8080` directly to the public Internet. Put it behind TLS and require a proxy
token, VPN, mTLS, or an IP allowlist.

## Requirements

- A Linux host with Docker Engine and Compose.
- A domain whose `A`/`AAAA` record points to the host.
- Inbound TCP ports 80 and 443; UDP 443 is optional for HTTP/3.

## Configuration

Clone the repository and create the root `.env`. At minimum configure:

```dotenv
UPSTREAM_URL=https://agentrouter.org
PORT=8080
ADMIN_TOKEN=long-random-admin-token
KEY_STORE_SECRET=independent-long-random-secret
KEY_STORE_PATH=/data/keys.json
KEY_SELECTION_MODE=pool-first
KEY_FAILOVER=true
KEY_COOLDOWN=5m
PROXY_AUTH_TOKEN=long-random-client-token
```

Copy the Caddy configuration and create the deployment environment:

```bash
cd deploy
cp Caddyfile.example Caddyfile
printf 'DOMAIN=api.example.com\n' > .env
docker compose -f docker-compose.host.yml up -d --build
```

Caddy obtains and renews a Let's Encrypt certificate automatically. The proxy
is reachable only through Caddy on the internal Docker network.

## Client setup

Use `https://api.example.com/v1` as the OpenAI base URL. Send the client access
token separately:

```text
X-Proxy-Token: value-from-PROXY_AUTH_TOKEN
```

The normal `Authorization: Bearer ...` header remains the AgentRouter API key
unless `KEY_SELECTION_MODE=pool-only` is active. If an IDE cannot send a custom
`X-Proxy-Token`, do not disable authentication; use a private WireGuard/Tailscale
network or enforce an IP/mTLS policy at the reverse proxy.

## Security checklist

- Keep `/admin` protected by a strong `ADMIN_TOKEN`.
- Keep `KEY_STORE_SECRET` backed up outside the host; losing it makes the
  encrypted key store unreadable.
- Bind no public host port for the proxy container itself.
- Restrict SSH and Docker socket access.
- Back up the named volumes before upgrades.
- Monitor `docker compose logs`, `/health`, and `/metrics`.
- Apply OS and container image updates regularly.
