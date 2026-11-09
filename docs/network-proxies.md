# Outbound network proxies

API upstream and network proxy are different entities. The upstream URL/protocol
still selects the LLM API. A network proxy only changes the path used to connect.

## Administration

`/admin` now has separate **Overview**, **Providers**, **API keys**, **Network proxies**,
**Client access**, and **Events** sections. Provider/model routing is described in
[providers.md](providers.md). Only the current section's data is
loaded; events are polled only while Events and the browser tab are visible.
Upstream keys have search (name/URL/model), 12-row pages, and collapsed advanced
priority/limits/pricing controls. Existing access, backup and policy controls remain.

1. Open **Network proxies**, choose **Add proxy**.
2. Enter a unique name and endpoint: `http://host:port`, `https://host:port` or
   `socks5://host:port`. No userinfo, path, query or fragment in the endpoint.
3. Enter optional username/password in separate fields. They are encrypted with
   the existing AES-GCM store. The API never returns them, including to admins.
4. Save. Enabled proxy membership changes automatically rebalance keys.
5. Use **Test** with a trusted HTTP(S) target. Default target is `UPSTREAM_URL`.
   This bounded 15s GET sends no provider API credential or WAF cookie. Receiving
   an HTTP response other than 407 confirms a response through the proxy, **not**
   a valid API key, external IP, or successful model generation. A proxy can itself
   return HTTP errors; run a real API request separately for end-to-end validation.
6. Edit a proxy to enable/disable it, update its endpoint or replace auth.
   Omitted/empty UI auth fields preserve existing credentials on edit; check
   **Remove saved authentication** to clear both explicitly.

**API keys → Routing and limits → Network route**:

- **Automatic**: stable assignment to one enabled network proxy.
- **Pinned**: choose one specific proxy; balancing never changes it.
- **Direct**: explicitly connect without a network proxy, ignoring HTTP_PROXY,
  HTTPS_PROXY and NO_PROXY for that key.

Network proxy management, probes and key policy changes require `admin` role.
`viewer` sees safe endpoints, binding counts and last-probe result only.

## Stable automatic balancing

The allocator balances **the number of assigned keys**, not instantaneous request
traffic. It includes manual pins when counting load; direct keys are excluded.
Disabled API keys retain an assigned route and count too, preventing changes just
because a key is toggled. Enabled network proxies participate in automatic allocation.

- New automatic keys go to the least-filled proxy.
- Adding/enabling/disabling/deleting proxies or changing key bindings triggers a
  deterministic rebalance. If counts differ by at most one, existing bindings stay.
- Only automatic keys move; move the minimum needed to remove count imbalance,
  choosing least-recently-used keys first. No per-request IP rotation, random
  changes, or movement based on lifetime usage/transient probe results.
- 20 automatic keys and 4 proxies normally result in 5 keys per proxy.
- Manual pins are respected even when they make perfect balance impossible.
- Existing HTTP requests and SSE streams keep their selected key/proxy snapshot
  and finish through the old route. Only future selections use the new assignment.
- There is no hard key limit, proxy traffic quota or global concurrency scheduler.
  Equal key counts cannot guarantee equal traffic when some keys are used more.

Transient connection/authentication failures do **not** silently reassign a key
or switch to direct access. This avoids IP churn and replaying potentially billed
POST requests. The failed route is recorded separately; the provider key is not
cooled for a transport error or explicit proxy 407. Fix/disable the route to move
its automatic keys to another enabled proxy. A pinned key stays blocked until the
operator changes its binding or enables/fixes its proxy. Deletion of a pinned
proxy is rejected until its keys are reassigned.

## Compatibility and fail-closed behavior

Old stores without a configured proxy pool keep the existing default transport,
including Go's environment-proxy behavior. Adding the first proxy activates the
managed pool and assigns all automatic/legacy stored keys (explicit Direct is
unchanged). Proxy settings do not apply to legacy inbound API keys, because those
have no stored binding: after activating the managed pool, default/inbound fallback
is disabled. Use stored credentials and `pool-only` for managed outbound routing.

If every proxy is disabled/deleted, automatic keys return
`503 network_proxy_unavailable`; they **do not** return to direct mode. The
persisted `settings.network_proxy_pool` flag remembers this decision even across
restarts. Explicitly set a key to Direct if direct access is intended. No enabled
API keys or a missing compatible protocol still use the previous routing errors.

HTTP 401/402/429 key failover remains supported: selecting a different key selects
its assigned network proxy and rebuilds the protocol adapter. Ambiguous POST
transport failures are not replayed by default. `RETRY_UNSAFE_REQUESTS` and
`RETRY_ON_5XX` remain explicit opt-ins with duplicate-execution/billing risk.
A managed proxy's 407 is not a provider-auth rejection and does not trigger key
failover. Other errors from a forward proxy can be indistinguishable from errors
from the upstream; this is not full end-to-end health diagnosis.

## Transports and WAF sessions

Standard Go transport implements authenticated HTTP forward proxy, CONNECT to
HTTPS targets, TLS to an HTTPS proxy, and SOCKS5 CONNECT with optional user/password
auth. SOCKS destination names are resolved by the SOCKS proxy. No new dependency,
UDP support, SOCKS4 adapter, NTLM/Kerberos auth or certificate-bypass switch is added.
Production validates TLS certificates for both HTTPS proxy and upstream normally.
SOCKS5 user/password auth itself is not encrypted; use only a trusted network.

Keep-alive connections and WAF cookies are separated by proxy ID/configuration;
multiple keys using the same proxy share its transport/session. Proxy auth or
endpoint edits create a fresh session. Explicit direct has a separate session
from legacy environment-proxy mode. Only the trusted default upstream origin with
non-generic spoof profile receives/captures AgentRouter WAF cookies. Warmup after
WAF rejection uses the **selected route**, never a different direct IP. The old
background direct warmup is suppressed while the managed pool is active; managed
routes acquire cookies on responses or WAF rejection. These sessions are in-memory.
Proxies that rotate their own exit IP may still invalidate WAF sessions externally.

## Security and storage

Use trusted network proxies: an HTTP target exposes API Authorization to the
forward proxy, and a proxy with TLS interception can observe traffic. Prefer HTTPS
upstream connections, trusted certificates and controlled egress. Proxy auth stays
in transport configuration; it is not copied into upstream request headers/logs.
Redirects are not followed. Probe targets and API URLs obey the existing
`UPSTREAM_ALLOWED_ORIGINS`; use network egress/DNS restrictions as well. Only
trusted operators may configure network proxy destinations, which are not bounded
by that API-upstream allowlist. Protect private/metadata networks at the firewall.

Records live in the existing v2 JSON's optional `network_proxies` array; usernames
and passwords are one AES-GCM ciphertext per record. Keys add `proxy_mode` and
`proxy_id`. Existing v1/v2 stores remain readable. File and PostgreSQL backups
include proxies, encrypted auth and bindings without exposing plaintext secrets.
Wrong encryption secret, malformed proxy nonce or missing referenced proxy rejects
import before replacing the in-memory pool. PostgreSQL stores the same JSON; Redis
is not a proxy allocator and no new distributed locking is claimed.

Back up the store/database and KEY_STORE_SECRET before upgrade. Never run an older
binary against a proxy-enabled store: it can discard unknown fields or bypass the
intended network route. For rollback keep the new encrypted backup untouched and
run the old image on a separate pre-upgrade volume/database copy. Do not change
KEY_STORE_SECRET or remove your backups.

## Admin API contracts

- `GET /api/admin/network-proxies`: safe `data` views (id, name, url, enabled,
  has_auth, assigned_keys, last_checked, last_error).
- `POST /api/admin/network-proxies`: `{name,url,enabled?,username?,password?}`;
  returns `{id}` with 201. Endpoint and name must be unique.
- `PATCH /api/admin/network-proxies/{id}`: same payload; name/url are required;
  omitted enabled/auth preserve previous values. Empty username/password clear auth.
- `DELETE /api/admin/network-proxies/{id}`: 204; rejects manual pins; automatically
  rebalances remaining automatic keys.
- `POST /api/admin/network-proxies/{id}/test`: `{target_url?}`; returns
  `{ok,status,message,duration_ms}`. Disabled routes can be tested before enabling.
- Key create/policy: `policy.proxy_mode` = `auto`, `fixed`, or `direct`;
  `policy.proxy_id` required for fixed. Omitted mode on policy update preserves
  the current binding. Safe key views return effective assigned `proxy_id`.

Example placeholders (never commit real credentials):

```json
{"name":"Outbound EU","url":"socks5://proxy.example:1080","enabled":true,"username":"REPLACE_USER","password":"REPLACE_PASSWORD"}
```
